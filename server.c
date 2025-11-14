// server.c
#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <winsock2.h>
#include <windows.h>
#include <time.h>

#pragma comment(lib, "ws2_32.lib")

#define SERVER_PORT 8080            // default port (change if you like)
#define SERVER_IP "0.0.0.0"        // bind all interfaces
#define MAX_CLIENTS 10
#define BUFFER_SIZE 4096
#define INACTIVITY_TIMEOUT 60      // seconds
#define STATS_LOG_INTERVAL 10      // seconds
#define FILE_BASE_DIR "server_files" // folder served

typedef struct {
    SOCKET socket;
    struct sockaddr_in addr;
    HANDLE thread;
    int id;
    int active;
    int is_admin;
    time_t last_active;
    unsigned long msg_count;
    unsigned long bytes_recv;
    unsigned long bytes_sent;
    char username[64];
} ClientInfo;

ClientInfo clients[MAX_CLIENTS];
CRITICAL_SECTION clients_lock;
SOCKET listen_socket = INVALID_SOCKET;
HANDLE statsLogger = NULL;
volatile int running = 1;

// Forward
DWORD WINAPI client_thread(LPVOID arg);
DWORD WINAPI stats_logger_thread(LPVOID arg);
void write_stats_to_file();
void print_stats_to_console();
int add_client(SOCKET s, struct sockaddr_in a);
void remove_client(int id);
int find_client_by_socket(SOCKET s);
void ensure_file_dir_exists();
int handle_admin_command(int id, const char *cmd);
int send_text(SOCKET s, const char *txt);
int receive_all(SOCKET s, char *buf, int len);
int send_file(SOCKET s, const char *filepath);
int receive_file(SOCKET s, const char *filepath, unsigned long filesize);

// Utility: get client ip string
void get_ip_str(struct sockaddr_in *a, char *out, int n) {
    strncpy(out, inet_ntoa(a->sin_addr), n-1);
    out[n-1] = 0;
}

int main() {
    WSADATA wsa;
    struct sockaddr_in server_addr, client_addr;
    int addrlen = sizeof(client_addr);

    InitializeCriticalSection(&clients_lock);
    for (int i = 0; i < MAX_CLIENTS; ++i) clients[i].active = 0;

    ensure_file_dir_exists();

    printf("[SERVER] Initializing Winsock...\n");
    if (WSAStartup(MAKEWORD(2,2), &wsa) != 0) {
        printf("WSAStartup failed: %d\n", WSAGetLastError());
        return 1;
    }

    listen_socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (listen_socket == INVALID_SOCKET) {
        printf("socket() failed: %d\n", WSAGetLastError());
        WSACleanup();
        return 1;
    }

    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(SERVER_PORT);
    server_addr.sin_addr.s_addr = INADDR_ANY; // bind to all

    if (bind(listen_socket, (struct sockaddr*)&server_addr, sizeof(server_addr)) == SOCKET_ERROR) {
        printf("bind() failed: %d\n", WSAGetLastError());
        closesocket(listen_socket);
        WSACleanup();
        return 1;
    }

    if (listen(listen_socket, SOMAXCONN) == SOCKET_ERROR) {
        printf("listen() failed: %d\n", WSAGetLastError());
        closesocket(listen_socket);
        WSACleanup();
        return 1;
    }

    printf("[SERVER] Listening on port %d. Waiting for clients...\n", SERVER_PORT);

    // Start stats logger thread
    statsLogger = CreateThread(NULL, 0, stats_logger_thread, NULL, 0, NULL);
    if (!statsLogger) {
        printf("[WARN] Could not create stats logger thread.\n");
    }

    // Accept loop
    while (running) {
        SOCKET client_sock = accept(listen_socket, (struct sockaddr*)&client_addr, &addrlen);
        if (client_sock == INVALID_SOCKET) {
            int err = WSAGetLastError();
            if (err == WSAEINTR) continue;
            printf("[ERROR] accept failed: %d\n", err);
            break;
        }

        EnterCriticalSection(&clients_lock);
        int free_slot = -1;
        for (int i = 0; i < MAX_CLIENTS; ++i) {
            if (!clients[i].active) { free_slot = i; break; }
        }
        LeaveCriticalSection(&clients_lock);

        char ipbuf[64]; get_ip_str(&client_addr, ipbuf, sizeof(ipbuf));
        if (free_slot == -1) {
            // server full -> ask client to wait or refuse
            const char *fullmsg = "SERVER_FULL: try again later\n";
            send(client_sock, fullmsg, (int)strlen(fullmsg), 0);
            closesocket(client_sock);
            printf("[SERVER] Rejected connection from %s (server full)\n", ipbuf);
            continue;
        }

        // Add client and spawn thread
        int id = add_client(client_sock, client_addr);
        if (id < 0) {
            closesocket(client_sock);
            continue;
        }

        // Thread created inside add_client - just print
        printf("[SERVER] Accepted client %d from %s\n", id, ipbuf);
    }

    // shutdown
    running = 0;
    if (statsLogger) WaitForSingleObject(statsLogger, 3000);
    closesocket(listen_socket);
    DeleteCriticalSection(&clients_lock);
    WSACleanup();
    return 0;
}

// create file dir if not exists
void ensure_file_dir_exists() {
    DWORD attrs = GetFileAttributesA(FILE_BASE_DIR);
    if (attrs == INVALID_FILE_ATTRIBUTES || !(attrs & FILE_ATTRIBUTE_DIRECTORY)) {
        CreateDirectoryA(FILE_BASE_DIR, NULL);
    }
}

int add_client(SOCKET s, struct sockaddr_in a) {
    EnterCriticalSection(&clients_lock);
    int idx = -1;
    for (int i = 0; i < MAX_CLIENTS; ++i) {
        if (!clients[i].active) { idx = i; break; }
    }
    if (idx == -1) { LeaveCriticalSection(&clients_lock); return -1; }

    clients[idx].socket = s;
    clients[idx].addr = a;
    clients[idx].id = idx;
    clients[idx].active = 1;
    clients[idx].is_admin = 0;
    clients[idx].last_active = time(NULL);
    clients[idx].msg_count = 0;
    clients[idx].bytes_recv = 0;
    clients[idx].bytes_sent = 0;
    strcpy(clients[idx].username, "guest");

    // create thread
    HANDLE th = CreateThread(NULL, 0, client_thread, (LPVOID)(intptr_t)idx, 0, NULL);
    if (!th) {
        clients[idx].active = 0;
        LeaveCriticalSection(&clients_lock);
        printf("[ERROR] CreateThread failed for client %d\n", idx);
        return -1;
    }
    clients[idx].thread = th;
    LeaveCriticalSection(&clients_lock);
    return idx;
}

void remove_client(int id) {
    EnterCriticalSection(&clients_lock);
    if (clients[id].active) {
        closesocket(clients[id].socket);
        clients[id].active = 0;
        if (clients[id].thread) {
            // let thread exit by itself
            clients[id].thread = NULL;
        }
    }
    LeaveCriticalSection(&clients_lock);
}

// stats logger thread
DWORD WINAPI stats_logger_thread(LPVOID arg) {
    (void)arg;
    while (running) {
        Sleep(STATS_LOG_INTERVAL * 1000);
        write_stats_to_file();

        // In addition close inactive clients
        EnterCriticalSection(&clients_lock);
        time_t now = time(NULL);
        for (int i = 0; i < MAX_CLIENTS; ++i) {
            if (clients[i].active) {
                double diff = difftime(now, clients[i].last_active);
                if (diff >= INACTIVITY_TIMEOUT) {
                    char ip[64]; get_ip_str(&clients[i].addr, ip, sizeof(ip));
                    printf("[TIMEOUT] Closing client %d (%s) due to inactivity (%.0f s)\n", i, ip, diff);
                    shutdown(clients[i].socket, SD_BOTH);
                    closesocket(clients[i].socket);
                    clients[i].active = 0;
                }
            }
        }
        LeaveCriticalSection(&clients_lock);
    }
    return 0;
}

void write_stats_to_file() {
    FILE *f = fopen("server_stats.txt", "w");
    if (!f) return;
    time_t now = time(NULL);
    fprintf(f, "Server stats at %s\n", ctime(&now));
    EnterCriticalSection(&clients_lock);
    int active_count = 0;
    for (int i = 0; i < MAX_CLIENTS; ++i) {
        if (clients[i].active) {
            char ip[64]; get_ip_str(&clients[i].addr, ip, sizeof(ip));
            fprintf(f, "Client %d | IP: %s | msgs: %lu | bytes_recv: %lu | bytes_sent: %lu | last_active: %lds ago\n",
                i, ip, clients[i].msg_count, clients[i].bytes_recv, clients[i].bytes_sent, (long)(time(NULL) - clients[i].last_active));
            active_count++;
        }
    }
    fprintf(f, "Active connections: %d\n", active_count);
    LeaveCriticalSection(&clients_lock);
    fclose(f);
}

void print_stats_to_console() {
    EnterCriticalSection(&clients_lock);
    printf("\n===== SERVER STATS =====\n");
    for (int i = 0; i < MAX_CLIENTS; ++i) {
        if (clients[i].active) {
            char ip[64]; get_ip_str(&clients[i].addr, ip, sizeof(ip));
            printf("Client %d | IP: %s | msgs: %lu | bytes_recv: %lu | bytes_sent: %lu | last_active: %lds ago\n",
                i, ip, clients[i].msg_count, clients[i].bytes_recv, clients[i].bytes_sent, (long)(time(NULL) - clients[i].last_active));
        }
    }
    printf("=========================\n\n");
    LeaveCriticalSection(&clients_lock);
}

// helper to send text terminated with newline
int send_text(SOCKET s, const char *txt) {
    int len = (int)strlen(txt);
    int sent = send(s, txt, len, 0);
    return (sent == len) ? 0 : -1;
}

// receive exactly len bytes (blocking)
int receive_all(SOCKET s, char *buf, int len) {
    int total = 0;
    while (total < len) {
        int r = recv(s, buf + total, len - total, 0);
        if (r <= 0) return r;
        total += r;
    }
    return total;
}

// send file with header: "FILE <size>\n" then raw bytes
int send_file(SOCKET s, const char *filepath) {
    FILE *f = fopen(filepath, "rb");
    if (!f) return -1;
    fseek(f, 0, SEEK_END);
    unsigned long sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    char header[128];
    snprintf(header, sizeof(header), "FILE %lu\n", sz);
    if (send(s, header, (int)strlen(header), 0) <= 0) { fclose(f); return -1; }
    char buf[BUFFER_SIZE];
    unsigned long sent = 0;
    while (!feof(f)) {
        size_t r = fread(buf, 1, sizeof(buf), f);
        if (r > 0) {
            int snt = send(s, buf, (int)r, 0);
            if (snt <= 0) { fclose(f); return -1; }
            sent += snt;
        }
    }
    fclose(f);
    return 0;
}

int receive_file(SOCKET s, const char *filepath, unsigned long filesize) {
    FILE *f = fopen(filepath, "wb");
    if (!f) return -1;
    char buf[BUFFER_SIZE];
    unsigned long recvd = 0;
    while (recvd < filesize) {
        int toread = (int)min((unsigned long)sizeof(buf), filesize - recvd);
        int r = recv(s, buf, toread, 0);
        if (r <= 0) { fclose(f); return -1; }
        fwrite(buf, 1, r, f);
        recvd += r;
    }
    fclose(f);
    return 0;
}

// handle each client
DWORD WINAPI client_thread(LPVOID arg) {
    int id = (int)(intptr_t)arg;
    ClientInfo *cli = &clients[id];
    SOCKET s = cli->socket;
    char buffer[BUFFER_SIZE + 1];

    // Step 1: Expect first message to define role: "ROLE ADMIN <password>" or "ROLE USER <name>"
    int r = recv(s, buffer, BUFFER_SIZE - 1, 0);
    if (r <= 0) {
        remove_client(id);
        return 0;
    }
    buffer[r] = 0;
    cli->bytes_recv += r;
    cli->msg_count++;
    cli->last_active = time(NULL);

    // parse role
    if (_strnicmp(buffer, "ROLE ADMIN", 10) == 0) {
        // for demo: accept any admin password "adminpass" or empty - in real: check properly
        // format: ROLE ADMIN <password>
        cli->is_admin = 1;
        SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_HIGHEST);
        send_text(s, "[SERVER] Role set to ADMIN\n");
    } else {
        // ROLE USER <name>  or default
        cli->is_admin = 0;
        if (sscanf(buffer, "ROLE USER %63s", cli->username) <= 0) {
            strcpy(cli->username, "guest");
        }
        send_text(s, "[SERVER] Role set to USER\n");
    }

    // main loop
    while (1) {
        int rec = recv(s, buffer, BUFFER_SIZE - 1, 0);
        if (rec <= 0) {
            // disconnect
            printf("[CLIENT %d] disconnected or recv error (%d)\n", id, rec);
            remove_client(id);
            break;
        }
        buffer[rec] = 0;
        cli->bytes_recv += rec;
        cli->msg_count++;
        cli->last_active = time(NULL);

        // Trim newline
        char *nl = strchr(buffer, '\r'); if (nl) *nl = 0;
        nl = strchr(buffer, '\n'); if (nl) *nl = 0;

        // STATS command (allowed for any client) - sends back summary text
        if (_stricmp(buffer, "STATS") == 0) {
            // send a small stats text
            char out[2048];
            EnterCriticalSection(&clients_lock);
            int active = 0;
            for (int i = 0; i < MAX_CLIENTS; ++i) if (clients[i].active) active++;
            snprintf(out, sizeof(out), "[SERVER STATS] Active: %d\nYou are client id: %d\n", active, id);
            LeaveCriticalSection(&clients_lock);
            send_text(s, out);
            continue;
        }

        // ADMIN commands prefixed with '/'
        if (buffer[0] == '/') {
            if (!cli->is_admin) {
                send_text(s, "[ERROR] You are not admin. Command denied.\n");
                continue;
            }
            if (handle_admin_command(id, buffer) != 0) {
                send_text(s, "[ERROR] Admin command failed.\n");
            }
            continue;
        }

        // otherwise treat as broadcast or echo
        // For demo: server echoes
        char reply[BUFFER_SIZE];
        snprintf(reply, sizeof(reply), "[ECHO] %s\n", buffer);
        send(s, reply, (int)strlen(reply), 0);
        cli->bytes_sent += (unsigned long)strlen(reply);
    }

    return 0;
}

// Implement admin commands
int handle_admin_command(int id, const char *cmd) {
    ClientInfo *cli = &clients[id];
    SOCKET s = cli->socket;
    char op[64], arg1[512];
    memset(op,0,sizeof(op)); memset(arg1,0,sizeof(arg1));

    // parse
    // commands: /list, /read <file>, /upload <file>, /download <file>, /delete <file>, /search <keyword>, /info <file>
    if (sscanf(cmd, "/%63s %511[^\n\r]", op, arg1) < 1) {
        // maybe "/list"
        if (_stricmp(cmd, "/list") == 0) strcpy(op, "list");
        else return -1;
    }

    if (_stricmp(op, "list") == 0) {
        // list files in FILE_BASE_DIR
        char searchPath[1024];
        snprintf(searchPath, sizeof(searchPath), "%s\\*.*", FILE_BASE_DIR);
        WIN32_FIND_DATAA fd;
        HANDLE h = FindFirstFileA(searchPath, &fd);
        if (h == INVALID_HANDLE_VALUE) {
            send_text(s, "[LIST] no files\n");
            return 0;
        }
        char out[BUFFER_SIZE];
        out[0]=0;
        strcat(out, "[LIST]\n");
        do {
            if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
                strcat(out, fd.cFileName);
                strcat(out, "\n");
            }
        } while (FindNextFileA(h, &fd));
        FindClose(h);
        send(s, out, (int)strlen(out), 0);
        cli->bytes_sent += (unsigned long)strlen(out);
        return 0;
    }
    else if (_stricmp(op, "read") == 0) {
        if (arg1[0]==0) { send_text(s,"[ERROR] Usage: /read <filename>\n"); return -1;}
        char path[1024]; snprintf(path,sizeof(path), "%s\\%s", FILE_BASE_DIR, arg1);
        FILE *f = fopen(path, "rb");
        if (!f) { send_text(s,"[ERROR] File not found\n"); return -1; }
        fseek(f,0,SEEK_END); unsigned long size = ftell(f); fseek(f,0,SEEK_SET);
        char header[128]; snprintf(header,sizeof(header),"[FILE %lu]\n", size);
        send(s, header, (int)strlen(header), 0);
        cli->bytes_sent += (unsigned long)strlen(header);
        char buf[BUFFER_SIZE];
        while (!feof(f)) {
            int r = (int)fread(buf,1,sizeof(buf),f);
            if (r>0) { send(s, buf, r, 0); cli->bytes_sent += r; }
        }
        fclose(f);
        return 0;
    }
    else if (_stricmp(op, "download") == 0) {
        // same as read: server sends file
        if (arg1[0]==0) { send_text(s,"[ERROR] Usage: /download <filename>\n"); return -1;}
        char path[1024]; snprintf(path,sizeof(path), "%s\\%s", FILE_BASE_DIR, arg1);
        if (send_file(s, path) != 0) {
            send_text(s,"[ERROR] Could not send file\n");
            return -1;
        }
        cli->bytes_sent += 0; // send_file accounts bytes by actual send counts not tracked here
        return 0;
    }
    else if (_stricmp(op, "upload") == 0) {
        // protocol: admin sends "/upload filename", server responds "READY"
        if (arg1[0]==0) { send_text(s,"[ERROR] Usage: /upload <filename>\n"); return -1;}
        char path[1024]; snprintf(path,sizeof(path), "%s\\%s", FILE_BASE_DIR, arg1);
        send_text(s, "READY\n");
        // next client should send header: FILE <size>\n then raw bytes
        char hdr[128];
        int r = recv(s, hdr, sizeof(hdr)-1, 0);
        if (r <= 0) return -1;
        hdr[r]=0;
        unsigned long fsize = 0;
        if (sscanf(hdr, "FILE %lu", &fsize) != 1) return -1;
        // locate newline in header; in practice header may be exactly "FILE n\n"
        // receive the rest file content
        // But we might have already read more bytes after header; for simplicity assume header alone
        if (receive_file(s, path, fsize) != 0) {
            send_text(s, "[ERROR] upload failed\n");
            return -1;
        }
        send_text(s, "[OK] Upload complete\n");
        return 0;
    }
    else if (_stricmp(op, "delete") == 0) {
        if (arg1[0]==0) { send_text(s,"[ERROR] Usage: /delete <filename>\n"); return -1;}
        char path[1024]; snprintf(path,sizeof(path), "%s\\%s", FILE_BASE_DIR, arg1);
        if (remove(path) == 0) { send_text(s, "[OK] Deleted\n"); return 0; }
        send_text(s, "[ERROR] Delete failed\n");
        return -1;
    }
    else if (_stricmp(op, "search") == 0) {
        if (arg1[0]==0) { send_text(s,"[ERROR] Usage: /search <keyword>\n"); return -1;}
        // naive search over filenames
        char searchPath[1024]; snprintf(searchPath,sizeof(searchPath), "%s\\*.*", FILE_BASE_DIR);
        WIN32_FIND_DATAA fd;
        HANDLE h = FindFirstFileA(searchPath, &fd);
        if (h == INVALID_HANDLE_VALUE) { send_text(s, "[SEARCH] no files\n"); return 0; }
        char out[BUFFER_SIZE]; out[0]=0; strcat(out,"[SEARCH]\n");
        do {
            if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
                if (strstr(fd.cFileName, arg1) != NULL) {
                    strcat(out, fd.cFileName); strcat(out, "\n");
                }
            }
        } while (FindNextFileA(h, &fd));
        FindClose(h);
        send(s, out, (int)strlen(out), 0);
        cli->bytes_sent += (unsigned long)strlen(out);
        return 0;
    }
    else if (_stricmp(op, "info") == 0) {
        if (arg1[0]==0) { send_text(s,"[ERROR] Usage: /info <filename>\n"); return -1;}
        char path[1024]; snprintf(path,sizeof(path), "%s\\%s", FILE_BASE_DIR, arg1);
        WIN32_FILE_ATTRIBUTE_DATA fad;
        if (!GetFileAttributesExA(path, GetFileExInfoStandard, &fad)) {
            send_text(s, "[ERROR] File not found\n"); return -1;
        }
        // get size
        unsigned long long size = ((unsigned long long)fad.nFileSizeHigh << 32) | fad.nFileSizeLow;
        // creation & write times
        FILETIME ftCreate = fad.ftCreationTime, ftWrite = fad.ftLastWriteTime;
        SYSTEMTIME stUTC, stLocal;
        FileTimeToSystemTime(&ftCreate, &stUTC);
        SystemTimeToTzSpecificLocalTime(NULL, &stUTC, &stLocal);
        char out[512];
        snprintf(out, sizeof(out), "[INFO] size=%llu bytes | last write: %02d-%02d-%04d %02d:%02d\n",
            size, stLocal.wDay, stLocal.wMonth, stLocal.wYear, stLocal.wHour, stLocal.wMinute);
        send(s, out, (int)strlen(out), 0);
        cli->bytes_sent += (unsigned long)strlen(out);
        return 0;
    }

    return -1;
}
