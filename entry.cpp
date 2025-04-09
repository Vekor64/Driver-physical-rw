#include "functions.h"
#include "comms.h"

#define WINDOWS_IGNORE_PACKING_MISMATCH

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
    UNREFERENCED_PARAMETER(RegistryPath);

    UNICODE_STRING DeviceName = RTL_CONSTANT_STRING(L"\\Device\\ApexDriver");
    UNICODE_STRING SymbolicLink = RTL_CONSTANT_STRING(L"\\??\\ApexDriver");
    PDEVICE_OBJECT DeviceObject;

    NTSTATUS Status = IoCreateDevice(
        DriverObject,
        0,
        &DeviceName,
        FILE_DEVICE_UNKNOWN,
        FILE_DEVICE_SECURE_OPEN,
        FALSE,
        &DeviceObject
    );

    if (!NT_SUCCESS(Status))
        return Status;
    DeviceObject->Flags = DO_BUFFERED_IO;

    Status = IoCreateSymbolicLink(&SymbolicLink, &DeviceName);
    if (!NT_SUCCESS(Status)) {
        IoDeleteDevice(DeviceObject);
        return Status;
    }

    for (ULONG i = 0; i < IRP_MJ_MAXIMUM_FUNCTION; i++)
        DriverObject->MajorFunction[i] = HandleDriverRequest;

    DriverObject->DriverUnload = DriverUnload;
    return STATUS_SUCCESS;
}

void DriverUnload(PDRIVER_OBJECT DriverObject)
{
    UNICODE_STRING SymbolicLink = RTL_CONSTANT_STRING(L"\\??\\ApexDriver");
    IoDeleteSymbolicLink(&SymbolicLink);
    IoDeleteDevice(DriverObject->DeviceObject);
}
