#ifndef UTILS_H
#define UTILS_H

#include <ntifs.h>
//#include <ntddk.h>
#include <Aux_klib.h>


#define DRIVER_NAME "SnitchHunt"
#define DRIVER_TAG 'cazz'

#pragma comment(lib, "Aux_klib.lib")


#define SYSTEM_DRV 0x8000
#define IOCTL_BASE 0x800

// Macro to build IOCTLs using METHOD_BUFFERED
#define CTL_CODE_HIDE(i) \
    CTL_CODE(SYSTEM_DRV, IOCTL_BASE + i, METHOD_BUFFERED, FILE_ANY_ACCESS)


#define IOCTL_KILL_PROCESS CTL_CODE_HIDE(1)
#define IOCTL_REM_PROC_CALLBACK CTL_CODE_HIDE(2)
#define IOCTL_LIST_PROC_CALLBACK CTL_CODE_HIDE(3)
#define IOCTL_LIST_THREAD_CALLBACK CTL_CODE_HIDE(4)
#define IOCTL_REM_THREAD_CALLBACK CTL_CODE_HIDE(5)
#define IOCTL_LIST_LOAD_IMAGE_CALLBACK CTL_CODE_HIDE(6)
#define IOCTL_REM_LOAD_IMAGE_CALLBACK CTL_CODE_HIDE(7)
#define IOCTL_LIST_REG_CALLBACK CTL_CODE_HIDE(8)
#define IOCTL_REM_REG_CALLBACK CTL_CODE_HIDE(9)



typedef enum _SYSTEM_INFORMATION_CLASS {
    SystemBasicInformation = 0,
    SystemPerformanceInformation = 2,
    SystemTimeOfDayInformation = 3,
    SystemProcessInformation = 5,
    SystemProcessorPerformanceInformation = 8,
    SystemInterruptInformation = 23,
    SystemExceptionInformation = 33,
    SystemRegistryQuotaInformation = 37,
    SystemLookasideInformation = 45,
    SystemCodeIntegrityInformation = 103,
    SystemPolicyInformation = 134,
} SYSTEM_INFORMATION_CLASS;

// Structure used for returning module name and base address
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


typedef struct _RTL_PROCESS_MODULE_INFORMATION
{
    ULONG Section;
    PVOID MappedBase;
    PVOID ImageBase;
    ULONG ImageSize;
    ULONG Flags;
    USHORT LoadOrderIndex;
    USHORT InitOrderIndex;
    USHORT LoadCount;
    USHORT OffsetToFileName;
    CHAR FullPathName[256];
} RTL_PROCESS_MODULE_INFORMATION, * PRTL_PROCESS_MODULE_INFORMATION;

typedef struct _RTL_PROCESS_MODULES
{
    ULONG NumberOfModules;
    RTL_PROCESS_MODULE_INFORMATION Modules[1];
} RTL_PROCESS_MODULES, * PRTL_PROCESS_MODULES;


typedef NTSTATUS(*PFN_ZwQuerySystemInformation)(
    SYSTEM_INFORMATION_CLASS SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength);


typedef enum _NOTIFY_ROUTINE_TYPE {
    ImageLoadCallback
} NOTIFY_ROUTINE_TYPE;


ModulesData* EnumRegisteredDrivers(UINT64);
UINT64 FindProcNotifyRoutineAddress(UINT64, NOTIFY_ROUTINE_TYPE);
UINT64 FindThreadNotifyRoutineAddress(UINT64, NOTIFY_ROUTINE_TYPE);
UINT64 FindLoadImageNotifyRoutineAddress(UINT64, NOTIFY_ROUTINE_TYPE);
UINT64 FindRegCallbackNotifyRoutineAddress(UINT64, NOTIFY_ROUTINE_TYPE);

NTSTATUS SearchModules(ULONG64, ModulesData*);
UINT64 FindKernelBase();
NTSTATUS DeleteNotifyEntry(ULONG64, int);
NTSTATUS DeleteRegCallbackEntry(ULONG64);


#ifndef SystemModuleInformation
#define SystemModuleInformation 0xB
#endif

#endif // !UTILS_H