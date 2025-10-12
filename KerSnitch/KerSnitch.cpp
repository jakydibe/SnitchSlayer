#include <ntifs.h>
//#include <ntddk.h>
#include <Aux_klib.h>


#pragma once


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



void UnloadMe(PDRIVER_OBJECT);
NTSTATUS DeviceControl(PDEVICE_OBJECT, PIRP);
NTSTATUS CreateClose(PDEVICE_OBJECT, PIRP);
UINT64 FindKernelBase();
//UINT64 FindProcNotifyRoutineAddress(UINT64, NOTIFY_ROUTINE_TYPE);


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




#ifndef SystemModuleInformation
#define SystemModuleInformation 0xB
#endif

UINT64 FindKernelBase() {
    UNICODE_STRING functionName;
	PFN_ZwQuerySystemInformation querySysInfo;
	NTSTATUS status;
    ULONG requiredSize;
    SIZE_T allocationSize;
    UINT64 kernelBase = 0;
    PRTL_PROCESS_MODULES moduleInfo = NULL;

	RtlInitUnicodeString(&functionName, L"ZwQuerySystemInformation");

	// dynamically get the address of ZwQuerySystemInformation
	querySysInfo = (PFN_ZwQuerySystemInformation)MmGetSystemRoutineAddress(&functionName);

    if (!querySysInfo) {
        DbgPrintEx(0, 0, "[%s] MmGetSystemRoutineAddress failed to get ZwQuerySystemInformation\n", DRIVER_NAME);
        return kernelBase;
	}

	status = querySysInfo((SYSTEM_INFORMATION_CLASS)SystemModuleInformation, NULL, 0, &requiredSize);

    if (status != STATUS_INFO_LENGTH_MISMATCH) {
        DbgPrintEx(0, 0, "[%s] ZwQuerySystemInformation failed to get size (0x%X)\n", DRIVER_NAME, status);
        return kernelBase;
	}

    allocationSize = requiredSize;
    while (status == STATUS_INFO_LENGTH_MISMATCH) {
        allocationSize += sizeof(ULONG);
        moduleInfo = (PRTL_PROCESS_MODULES)ExAllocatePool2(POOL_FLAG_NON_PAGED, allocationSize, 'Tag1');
        if (!moduleInfo) {
            DbgPrintEx(0, 0, "[%s] ExAllocatePool2 failed\n", DRIVER_NAME);
            return kernelBase;
        }
        status = querySysInfo((SYSTEM_INFORMATION_CLASS)SystemModuleInformation, moduleInfo, (ULONG)allocationSize, &requiredSize);
        if (status == STATUS_INFO_LENGTH_MISMATCH) {
            ExFreePoolWithTag(moduleInfo, 'Tag1');
            moduleInfo = NULL;
        }
    }
    if (!NT_SUCCESS(status)) {
        if (moduleInfo) {
			ExFreePoolWithTag(moduleInfo, 'Tag1');
        }
        return kernelBase;
	}
	kernelBase = (UINT64)moduleInfo->Modules[0].ImageBase;
    ExFreePoolWithTag(moduleInfo, 'Tag1');
	return kernelBase;
}


NTSTATUS SearchModules(ULONG64 ModuleAddr, ModulesData* ModuleFound) {
	NTSTATUS status = STATUS_SUCCESS;
	ULONG modulesSize = 0;
    AUX_MODULE_EXTENDED_INFO* modules = NULL;
	ULONG numberOfModules = 0;

    // Step 1: Initialize the Auxiliary Kernel Library
    status = AuxKlibInitialize();
    if (!NT_SUCCESS(status))
    {
        DbgPrintEx(0, 0, "[%s] AuxKlibInitialize fail %d\n", DRIVER_NAME, status);
        return status;
    }	
    
    ModulesData ModuleFound2 = *ModuleFound;
    // take info abt kernel drivers
	status = AuxKlibQueryModuleInformation(&modulesSize, sizeof(AUX_MODULE_EXTENDED_INFO), NULL);

    if (!NT_SUCCESS(status) || modulesSize == 0) {
        DbgPrintEx(0, 0, "[%s] AuxKlibQueryModuleInformation failed to get size (0x%X)\n", DRIVER_NAME, status);
        return status;
    }

	numberOfModules = modulesSize / sizeof(AUX_MODULE_EXTENDED_INFO);

	modules = (AUX_MODULE_EXTENDED_INFO*)ExAllocatePool2(POOL_FLAG_PAGED, modulesSize, DRIVER_TAG);
    if (modules == NULL) {
        DbgPrintEx(0, 0, "[%s] ExAllocatePool2 failed\n", DRIVER_NAME);
        return STATUS_INSUFFICIENT_RESOURCES;
	}
    // Query module information into the allocated buffer
	status = AuxKlibQueryModuleInformation(&modulesSize, sizeof(AUX_MODULE_EXTENDED_INFO), modules);
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(0, 0, "[%s] AuxKlibQueryModuleInformation failed (0x%X)\n", DRIVER_NAME, status);
        ExFreePoolWithTag(modules, DRIVER_TAG);
        return status;
	}


	DbgPrintEx(0, 0, "[%s] Searching for module containing address: 0x%llx\n", DRIVER_NAME, ModuleAddr);
    for (ULONG i = 0; i < numberOfModules; i++) {
   //     DbgPrintEx(0, 0, "[%s] Module %d: %s at base address: 0x%llx, size: 0x%x\n",
   //         DRIVER_NAME,
   //         i,
   //         (PCSTR)&modules[i].FullPathName[modules[i].FileNameOffset],
   //         (ULONG64)modules[i].BasicInfo.ImageBase,
			//modules[i].ImageSize);
        if ((ModuleAddr > (ULONG64)modules[i].BasicInfo.ImageBase) && (ModuleAddr < ((ULONG64)modules[i].BasicInfo.ImageBase + modules[i].ImageSize))) {
            //DbgPrintEx(0, 0, "[%s] Found module: %s at base address: 0x%llx\n",
            //    DRIVER_NAME,
            //    (PCSTR)&modules[i].FullPathName[modules[i].FileNameOffset],
            //    (ULONG64)modules[i].BasicInfo.ImageBase);


			strcpy(ModuleFound2.ModuleName, (CHAR*)(modules[i].FullPathName + modules[i].FileNameOffset));
			*ModuleFound = ModuleFound2;

			DbgPrintEx(0, 0, "[%s] Module name: %s\n", DRIVER_NAME, ModuleFound2.ModuleName);
			ExFreePoolWithTag(modules, DRIVER_TAG);
			return status;
        }
    }

	ExFreePoolWithTag(modules, DRIVER_TAG);
	return status;

}


//NTSTATUS

UINT64 FindProcNotifyRoutineAddress(UINT64 kernelBase, NOTIFY_ROUTINE_TYPE callbackType) {
    UINT64 routineAddress = 0;
    UINT64 tempAddress = 0;
    UINT64 notifyArrayAddress = 0;
    UNICODE_STRING routineName;

	UNREFERENCED_PARAMETER(kernelBase);
	UNREFERENCED_PARAMETER(callbackType);

	RtlInitUnicodeString(&routineName, L"PsSetCreateProcessNotifyRoutine");

    
	routineAddress = (UINT64)MmGetSystemRoutineAddress(&routineName);
    if(!routineAddress) {
        DbgPrintEx(0, 0, "[%s] MmGetSystemRoutineAddress failed to get PsSetCreateProcessNotifyRoutine\n", DRIVER_NAME);
        return 0;
	}
	// PRATICAMENTE TROVIAMO LA CALL A PspSetCreateProcessNotifyRoutine. PsSetCreateProcessNotifyRoutine FA UNA CALL A PspSetCreateProcessNotifyRoutine CHE A SUA VOLTA FA UNA LEA CHE CARICA L'INDIRIZZO DELL'ARRAY DI CALLBACK IN R13
    for (int offset = 0; offset < 0x100; offset++) {
		unsigned char instruction = *((unsigned char*)(routineAddress + offset));
        if (instruction == 0xe9 || instruction == 0xe8) { // CALL or JMP
			LONG relativeOffset = *((LONG*)(routineAddress + offset + 1));

			tempAddress = routineAddress + offset + 5 + relativeOffset;
            break;
        }
    }
    if (!tempAddress) {
        DbgPrintEx(0, 0, "[%s] Failed to find call/jmp instruction in PsSetCreateProcessNotifyRoutine\n", DRIVER_NAME);
        return 0;
	}

    //effettivamente la prima lea di PspSetCreateProcessNotifyRoutine. carica in r13 l'indirizzo di PspCreateProcessNotifyRoutine

    for (int offset = 0; offset < 300; offset++) {
		unsigned char prefix = *((unsigned char*)(tempAddress + offset));
        if ((prefix == 0x48 || prefix == 0x4C) && (*(unsigned char*)(tempAddress + offset + 1) == 0x8D)) { // LEA
            LONG relativeOffset = *((LONG*)(tempAddress + offset + 3));

            notifyArrayAddress = tempAddress + offset + 7 + relativeOffset;
            break;
        }
    }

	return notifyArrayAddress;
}


void EnumProcRegisteredDrivers(UINT64 procNotifyArrayAddr) {
    ModulesData moduleInfo = { 0 };
    NTSTATUS status = STATUS_SUCCESS;
    UINT64 callbackAddr = 0;
    UINT64 tmpPtr = 0;
    //LPVOID* 


    
    for (int i = 0; i < 64; i++) {
        tmpPtr = procNotifyArrayAddr + i * 8;
		callbackAddr = *(PUINT64)(tmpPtr);

        //callbackAddr = *(callbackAddr & 0xfffffffffffffff8); // Mask to get the actual address (for x64 systems)

		//DbgPrintEx(0, 0, "[%s] Process Notify Callback %d Address: 0x%llx\n", DRIVER_NAME, i, callbackAddr);

		if (callbackAddr && MmIsAddressValid((PVOID)callbackAddr)) {
			callbackAddr = *(PUINT64)(callbackAddr & 0xfffffffffffffff8); // Mask to get the actual address (for x64 systems)
            status = SearchModules(callbackAddr, &moduleInfo);
            if (NT_SUCCESS(status)) {
                DbgPrintEx(0, 0, "[%s] Process Notify Callback %d: 0x%llx in module %s\n", DRIVER_NAME, i, callbackAddr, (PCSTR)moduleInfo.ModuleName);
            }
            else {
                DbgPrintEx(0, 0, "[%s] Process Notify Callback %d: 0x%llx in unknown module\n", DRIVER_NAME, i, callbackAddr);
            }
        }
	}
}



// Handle IRP_MJ_CREATE and IRP_MJ_CLOSE
NTSTATUS CreateClose(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
	UNREFERENCED_PARAMETER(DeviceObject);

	Irp->IoStatus.Status = STATUS_SUCCESS;
	Irp->IoStatus.Information = 0;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}


extern "C" NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {
	
	UNREFERENCED_PARAMETER(RegistryPath);

	DbgPrintEx(0, 0, "[%s] SnitchHunter started hunting snitches. Callback on deez nutz loosers\n", DRIVER_NAME);


	DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DeviceControl;
	DriverObject->MajorFunction[IRP_MJ_CREATE] = CreateClose;
	DriverObject->MajorFunction[IRP_MJ_CLOSE] = CreateClose;

	// Unload Function
	DriverObject->DriverUnload = UnloadMe;


	UNICODE_STRING devName = RTL_CONSTANT_STRING(L"\\Device\\SnitchHunt");

	PDEVICE_OBJECT DeviceObject;

	NTSTATUS status = IoCreateDevice(
		DriverObject,
		0,
		&devName,
		FILE_DEVICE_UNKNOWN,
		FILE_DEVICE_SECURE_OPEN,
		FALSE,
		&DeviceObject);

	if (!NT_SUCCESS(status)) {
		DbgPrintEx(0, 0, "[%s] Failed to create device (0x%X)\n", DRIVER_NAME, status);
		return status;
	}

	UNICODE_STRING symLink = RTL_CONSTANT_STRING(L"\\??\\SnitchHunt");
	status = IoCreateSymbolicLink(&symLink, &devName);
	if (!NT_SUCCESS(status)) {
		IoDeleteDevice(DeviceObject);
		DbgPrintEx(0, 0, "[%s] Failed to create symbolic link (0x%X)\n", DRIVER_NAME, status);
		return status;
	}

	return STATUS_SUCCESS;
}




NTSTATUS DeviceControl(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);

    NTSTATUS status = STATUS_SUCCESS;
    ULONG_PTR info = 0;

    PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(Irp);
    ULONG controlCode = stack->Parameters.DeviceIoControl.IoControlCode;

    switch (controlCode) {
    case IOCTL_KILL_PROCESS:
    {
        //if (stack->Parameters.DeviceIoControl.InputBufferLength < sizeof(ULONG_PTR) ||
        //    Irp->AssociatedIrp.SystemBuffer == NULL) {
        //    status = STATUS_BUFFER_TOO_SMALL;
        //    break;
        //}

        ULONG_PTR pidVal = *(ULONG_PTR*)Irp->AssociatedIrp.SystemBuffer;

        HANDLE hProcess = NULL;
        OBJECT_ATTRIBUTES oa;
        CLIENT_ID cid;

        InitializeObjectAttributes(&oa, NULL, 0, NULL, NULL);
        cid.UniqueProcess = (HANDLE)pidVal;
        cid.UniqueThread = NULL;

        status = ZwOpenProcess(&hProcess, 1, &oa, &cid);
        if (!NT_SUCCESS(status)) {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                "[%s] ZwOpenProcess failed for PID %llu (0x%08X)\n",
                DRIVER_NAME, (unsigned long long)pidVal, status);
            break;
        }

        status = ZwTerminateProcess(hProcess, STATUS_SUCCESS);
        if (!NT_SUCCESS(status)) {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                "[%s] ZwTerminateProcess failed for PID %llu (0x%08X)\n",
                DRIVER_NAME, (unsigned long long)pidVal, status);
        }
        else {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
                "[%s] Terminated PID %llu\n",
                DRIVER_NAME, (unsigned long long)pidVal);
        }

        ZwClose(hProcess);
        break;
    }
    case IOCTL_LIST_PROC_CALLBACK:
    {
        // Placeholder for listing process callbacks
		UINT64 kernelBase = FindKernelBase();
        if (!kernelBase) {
            DbgPrintEx(0, 0, "[%s] Failed to find kernel base\n", DRIVER_NAME);
            status = STATUS_UNSUCCESSFUL;
            break;
		}

        ULONG64 procNotifyArrayAddr = FindProcNotifyRoutineAddress(kernelBase, ImageLoadCallback);
        if (!procNotifyArrayAddr) {
            DbgPrintEx(0, 0, "[%s] Failed to find process notify routine address\n", DRIVER_NAME);
            status = STATUS_UNSUCCESSFUL;
            break;
		}

        //procNotifyArrayAddr = *(PULONG64)(procNotifyArrayAddr & 0xfffffffffffffff8);

		DbgPrintEx(0, 0, "[%s] Process Notify Routine Array Address: 0x%llx\n", DRIVER_NAME, procNotifyArrayAddr);

		EnumProcRegisteredDrivers(procNotifyArrayAddr);

		// send back packet with base address of procNotifyArrayAddr
		ULONG_PTR* outputBuffer = (ULONG_PTR*)Irp->AssociatedIrp.SystemBuffer;
        if (outputBuffer && stack->Parameters.DeviceIoControl.OutputBufferLength >= sizeof(ULONG_PTR)) {
            *outputBuffer = procNotifyArrayAddr;
            info = sizeof(ULONG_PTR);
            status = STATUS_SUCCESS;
        }
        else {
            status = STATUS_BUFFER_TOO_SMALL;
        }
		break;
	}
    default:
        status = STATUS_INVALID_DEVICE_REQUEST;
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
            "[%s] Invalid IOCTL 0x%08X\n", DRIVER_NAME, controlCode);
        break;
    }

    // Complete the IRP
    Irp->IoStatus.Status = status;
    Irp->IoStatus.Information = info; // bytes returned (0 here)
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return status;
}

void UnloadMe(PDRIVER_OBJECT DriverObject) {
	UNREFERENCED_PARAMETER(DriverObject);
	UNICODE_STRING symLink = RTL_CONSTANT_STRING(L"\\??\\SnitchHunt");

	IoDeleteSymbolicLink(&symLink);             // Remove user-mode access path
	IoDeleteDevice(DriverObject->DeviceObject); // Delete the device object

	DbgPrintEx(0, 0, "[%s] Driver has been Unloaded.\n", DRIVER_NAME);
	DbgPrint("Bye Bye from HelloWorld Driver\n");
}