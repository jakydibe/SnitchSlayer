#include <ntddk.h>
#include <wdf.h>
#include <wdm.h>


DRIVER_INITIALIZE DriverEntry;

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
    UNREFERENCED_PARAMETER(DriverObject);
    UNREFERENCED_PARAMETER(RegistryPath);

    DbgPrint("Hello from driver!\n");
    return STATUS_SUCCESS;
}