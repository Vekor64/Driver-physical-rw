#pragma once
#include "globals.h"

EXTERN_C NTSTATUS __declspec(dllexport) DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath);
void DriverUnload(PDRIVER_OBJECT DriverObject);

NTSTATUS ReadPhysicalMemory(HANDLE ProcessId, PVOID SourceAddress, PVOID TargetAddress, SIZE_T Size);
NTSTATUS WritePhysicalMemory(HANDLE ProcessId, PVOID TargetAddress, PVOID SourceAddress, SIZE_T Size);

NTSTATUS ProtectProcess(HANDLE ProcessId);

NTSTATUS GetModuleBase(HANDLE ProcessId, LPCSTR ModuleName, PVOID* BaseAddress);

NTSTATUS AllocateVirtualMemory(
    HANDLE ProcessId,
    PVOID* BaseAddress,
    SIZE_T Size,
    ULONG AllocationType,
    ULONG Protect
);

NTSTATUS FreeVirtualMemory(
    HANDLE ProcessId,
    PVOID BaseAddress
);

NTSTATUS ProtectVirtualMemory(
    HANDLE ProcessId,
    PVOID BaseAddress,
    SIZE_T Size,
    ULONG NewProtect,
    PULONG OldProtect
);

NTSTATUS CopyVirtualMemory(
    HANDLE SourceProcessId,
    PVOID SourceAddress,
    HANDLE TargetProcessId,
    PVOID TargetAddress,
    SIZE_T Size
);

NTSTATUS CallKernelFunction(
    HANDLE ProcessId,
    PVOID EntryPoint,
    PVOID Context
);

NTSTATUS HandleDriverRequest(PDEVICE_OBJECT DeviceObject, PIRP Irp);