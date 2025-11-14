// server.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <winsock2.h>
#include <windows.h>

#pragma comment(lib, "ws2_32.lib") 

#define PORT 8080
#define BUFFER_SIZE 1024

DWORD WINAPI clientHandler(void *clientSocketPtr);

int main() {
    WSADATA wsa;
    SOCKET serverSocket, clientSocket;
    struct sockaddr_in server, client;
    int c;

    printf("[+] Initializing Winsock...\n");
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        printf("[-] Winsock initialization failed. Error Code: %d\n", WSAGetLastError());
        return 1;
    }
    printf("[+] Winsock initialized.\n");

    // Krijojme nje socket
    serverSocket = socket(AF_INET, SOCK_STREAM, 0);
    if (serverSocket == INVALID_SOCKET) {
        printf("[-] Could not create socket. Error Code: %d\n", WSAGetLastError());
        WSACleanup();
        return 1;
    }
    printf("[+] Socket created.\n");

    // Pregadisim strukturen sockaddr_in 
    server.sin_family = AF_INET;
    server.sin_addr.s_addr = INADDR_ANY;
    server.sin_port = htons(PORT);

    // Bindi
    if (bind(serverSocket, (struct sockaddr *)&server, sizeof(server)) == SOCKET_ERROR) {
        printf("[-] Bind failed. Error Code: %d\n", WSAGetLastError());
        closesocket(serverSocket);
        WSACleanup();
        return 1;
    }
    printf("[+] Bind done on port %d.\n", PORT);

    // Listen - funksioni
    listen(serverSocket, 3);
    printf("[+] Waiting for incoming connections...\n");

    c = sizeof(struct sockaddr_in);

    while ((clientSocket = accept(serverSocket, (struct sockaddr *)&client, &c)) != INVALID_SOCKET) {
        printf("[+] Client connected! IP: %s\n", inet_ntoa(client.sin_addr));

        // Krijojme thread-a te vecante per secilin l;ient
        HANDLE hThread = CreateThread(
            NULL,               // default atributet e sigurise
            0,                  // default madhesia e stack-ut
            clientHandler,      // thread - funksioni
            (void*)clientSocket,// parametrat e thread-it
            0,                  // default krijimi i flags
            NULL                // thread ID
        );

        if (hThread == NULL) {
            printf("[-] Failed to create thread for client.\n");
            closesocket(clientSocket);
        } else {
            CloseHandle(hThread); 
        }
    }

    if (clientSocket == INVALID_SOCKET) {
        printf("[-] Accept failed. Error Code: %d\n", WSAGetLastError());
    }

    closesocket(serverSocket);
    WSACleanup();

    return 0;
}

DWORD WINAPI clientHandler(void *clientSocketPtr) {
    SOCKET clientSocket = (SOCKET)clientSocketPtr;
    char buffer[BUFFER_SIZE];
    int readSize;

    printf("[Thread] Handling client...\n");

    
    
    while ((readSize = recv(clientSocket, buffer, BUFFER_SIZE, 0)) > 0) {
        buffer[readSize] = '\0';
        printf("[Client says]: %s\n", buffer);

       
        send(clientSocket, buffer, readSize, 0);
    }

    if (readSize == 0) {
        printf("[+] Client disconnected.\n");
    } else {
        printf("[-] recv() failed. Error Code: %d\n", WSAGetLastError());
    }

    closesocket(clientSocket);
    return 0;
}
