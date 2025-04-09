#pragma once
#include "globals.h"

// 驱动函数声明
EXTERN_C NTSTATUS __declspec(dllexport) DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath);
void DriverUnload(PDRIVER_OBJECT DriverObject);

// 内存操作函数
NTSTATUS ReadPhysicalMemory(HANDLE ProcessId, PVOID SourceAddress, PVOID TargetAddress, SIZE_T Size);
NTSTATUS WritePhysicalMemory(HANDLE ProcessId, PVOID TargetAddress, PVOID SourceAddress, SIZE_T Size);

// 进程保护函数
NTSTATUS ProtectProcess(HANDLE ProcessId);

// 基址获取函数
NTSTATUS GetModuleBase(HANDLE ProcessId, LPCSTR ModuleName, PVOID* BaseAddress);

// 虚拟内存操作函数
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

// 入口点调用函数
NTSTATUS CallKernelFunction(
    HANDLE ProcessId,
    PVOID EntryPoint,
    PVOID Context
);

// 通信请求处理函数
NTSTATUS HandleDriverRequest(PDEVICE_OBJECT DeviceObject, PIRP Irp);