#import "utils.h"



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
