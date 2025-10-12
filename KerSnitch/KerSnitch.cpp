#include <ntifs.h>

#define DRIVER_NAME "SnitchHunt"




#define SYSTEM_DRV 0x8000
#define IOCTL_BASE 0x800

// Macro to build IOCTLs using METHOD_BUFFERED
#define CTL_CODE_HIDE(i) \
    CTL_CODE(SYSTEM_DRV, IOCTL_BASE + i, METHOD_BUFFERED, FILE_ANY_ACCESS)


#define IOCTL_KILL_PROCESS CTL_CODE_HIDE(1)



void UnloadMe(PDRIVER_OBJECT);
NTSTATUS DeviceControl(PDEVICE_OBJECT DeviceObject, PIRP Irp);
NTSTATUS CreateClose(PDEVICE_OBJECT DeviceObject, PIRP Irp);



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