#include "functions.h"
#include "comms.h"

// 内存读写操作
NTSTATUS ReadPhysicalMemory(HANDLE ProcessId, PVOID SourceAddress, PVOID TargetAddress, SIZE_T Size)
{
    PEPROCESS SourceProcess;
    NTSTATUS Status = PsLookupProcessByProcessId(ProcessId, &SourceProcess);
    if (!NT_SUCCESS(Status))
        return Status;

    // 获取源地址对应的物理地址
    KAPC_STATE ApcState;
    KeStackAttachProcess(SourceProcess, &ApcState);
    PHYSICAL_ADDRESS PhysicalAddr = MmGetPhysicalAddress(SourceAddress);
    KeUnstackDetachProcess(&ApcState);

    if (PhysicalAddr.QuadPart == 0)
    {
        ObDereferenceObject(SourceProcess);
        return STATUS_INVALID_ADDRESS;
    }

    // 映射物理地址到系统空间
    PVOID MappedMemory = MmMapIoSpace(PhysicalAddr, Size, MmNonCached);
    if (!MappedMemory)
    {
        ObDereferenceObject(SourceProcess);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    // 复制内存内容
    RtlCopyMemory(TargetAddress, MappedMemory, Size);

    // 取消映射
    MmUnmapIoSpace(MappedMemory, Size);

    ObDereferenceObject(SourceProcess);
    return STATUS_SUCCESS;
}

NTSTATUS WritePhysicalMemory(HANDLE ProcessId, PVOID TargetAddress, PVOID SourceAddress, SIZE_T Size)
{
    PEPROCESS TargetProcess;
    NTSTATUS Status = PsLookupProcessByProcessId(ProcessId, &TargetProcess);
    if (!NT_SUCCESS(Status))
        return Status;

    // 获取目标地址对应的物理地址
    KAPC_STATE ApcState;
    KeStackAttachProcess(TargetProcess, &ApcState);
    PHYSICAL_ADDRESS PhysicalAddr = MmGetPhysicalAddress(TargetAddress);
    KeUnstackDetachProcess(&ApcState);

    if (PhysicalAddr.QuadPart == 0)
    {
        ObDereferenceObject(TargetProcess);
        return STATUS_INVALID_ADDRESS;
    }

    // 映射物理地址到系统空间
    PVOID MappedMemory = MmMapIoSpace(PhysicalAddr, Size, MmNonCached);
    if (!MappedMemory)
    {
        ObDereferenceObject(TargetProcess);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    // 复制内存内容
    RtlCopyMemory(MappedMemory, SourceAddress, Size);

    // 取消映射
    MmUnmapIoSpace(MappedMemory, Size);

    ObDereferenceObject(TargetProcess);
    return STATUS_SUCCESS;
}

// 进程保护
NTSTATUS ProtectProcess(HANDLE ProcessId)
{
    PEPROCESS Process;
    NTSTATUS Status = PsLookupProcessByProcessId(ProcessId, &Process);
    if (!NT_SUCCESS(Status))
        return Status;

    // 获取进程对象头部
    PUCHAR ProcessObject = (PUCHAR)Process;

    // 修改进程保护标志
    // 偏移0x87A是Windows进程对象中的Protection字段
    // 设置为1表示启用保护
    *(PUCHAR)(ProcessObject + 0x87A) = 1;

    ObDereferenceObject(Process);
    return STATUS_SUCCESS;
}

// 获取模块基址
NTSTATUS GetModuleBase(HANDLE ProcessId, LPCSTR ModuleName, PVOID* BaseAddress)
{
    if (!ModuleName || !BaseAddress) {
        return STATUS_INVALID_PARAMETER;
    }
    
    *BaseAddress = NULL;
    
    PEPROCESS Process;
    NTSTATUS Status = PsLookupProcessByProcessId(ProcessId, &Process);
    if (!NT_SUCCESS(Status))
        return Status;
    
    __try {
        KAPC_STATE ApcState;
        KeStackAttachProcess(Process, &ApcState);
        
        __try {
            PPEB Peb = PsGetProcessPeb(Process);
            if (!Peb) {
                Status = STATUS_UNSUCCESSFUL;
                __leave;
            }
            
            // 检查是否请求的是主模块（EXE）
            if (_stricmp(ModuleName, "") == 0 || _stricmp(ModuleName, "exe") == 0) {
                // 返回进程的主模块基址
                *BaseAddress = Peb->ImageBaseAddress;
                Status = *BaseAddress ? STATUS_SUCCESS : STATUS_NOT_FOUND;
                __leave;
            }
            
            if (!Peb->Ldr) {
                Status = STATUS_UNSUCCESSFUL;
                __leave;
            }
            
            PPEB_LDR_DATA Ldr = Peb->Ldr;
            PLIST_ENTRY ModuleList = &Ldr->InLoadOrderModuleList;
            PLIST_ENTRY Entry = ModuleList->Flink;
            
            // 遍历模块列表
            while (Entry && Entry != ModuleList) {
                PLDR_DATA_TABLE_ENTRY Module = CONTAINING_RECORD(Entry, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
                
                // 安全检查
                if (!Module || !Module->BaseDllName.Buffer) {
                    Entry = Entry->Flink;
                    continue;
                }
                
                // 转换模块名称为ANSI字符串进行比较
                char ModuleNameBuffer[256] = {0};
                ULONG ConvertedLength = 0;
                
                Status = RtlUnicodeToMultiByteN(
                    ModuleNameBuffer,
                    sizeof(ModuleNameBuffer) - 1,
                    &ConvertedLength,
                    Module->BaseDllName.Buffer,
                    Module->BaseDllName.Length
                );
                
                if (NT_SUCCESS(Status)) {
                    ModuleNameBuffer[ConvertedLength] = '\0';
                    
                    // 比较模块名称（不区分大小写）
                    if (_stricmp(ModuleNameBuffer, ModuleName) == 0) {
                        *BaseAddress = Module->DllBase;
                        Status = STATUS_SUCCESS;
                        __leave;
                    }
                }
                
                // 移动到下一个条目
                Entry = Entry->Flink;
            }
            
            // 如果没有找到匹配的模块
            Status = STATUS_NOT_FOUND;
        }
        __finally {
            KeUnstackDetachProcess(&ApcState);
        }
    }
    __except(EXCEPTION_EXECUTE_HANDLER) {
        Status = GetExceptionCode();
    }
    
    ObDereferenceObject(Process);
    return Status;
}

// 虚拟内存操作
NTSTATUS AllocateVirtualMemory(
    HANDLE ProcessId,
    PVOID* BaseAddress,
    SIZE_T Size,
    ULONG AllocationType,
    ULONG Protect)
{
    PEPROCESS Process;
    NTSTATUS Status = PsLookupProcessByProcessId(ProcessId, &Process);
    if (!NT_SUCCESS(Status))
        return Status;

    KAPC_STATE ApcState;
    KeStackAttachProcess(Process, &ApcState);

    Status = ZwAllocateVirtualMemory(
        NtCurrentProcess(),
        BaseAddress,
        0,
        &Size,
        AllocationType,
        Protect
    );

    KeUnstackDetachProcess(&ApcState);
    ObDereferenceObject(Process);
    return Status;
}

NTSTATUS FreeVirtualMemory(HANDLE ProcessId, PVOID BaseAddress)
{
    PEPROCESS Process;
    NTSTATUS Status = PsLookupProcessByProcessId(ProcessId, &Process);
    if (!NT_SUCCESS(Status))
        return Status;

    KAPC_STATE ApcState;
    KeStackAttachProcess(Process, &ApcState);

    SIZE_T Size = 0;
    Status = ZwFreeVirtualMemory(
        NtCurrentProcess(),
        &BaseAddress,
        &Size,
        MEM_RELEASE
    );

    KeUnstackDetachProcess(&ApcState);
    ObDereferenceObject(Process);
    return Status;
}

NTSTATUS ProtectVirtualMemory(
    HANDLE ProcessId,
    PVOID BaseAddress,
    SIZE_T Size,
    ULONG NewProtect,
    PULONG OldProtect)
{
    PEPROCESS Process;
    NTSTATUS Status = PsLookupProcessByProcessId(ProcessId, &Process);
    if (!NT_SUCCESS(Status))
        return Status;

    KAPC_STATE ApcState;
    KeStackAttachProcess(Process, &ApcState);

    Status = ZwProtectVirtualMemory(
        NtCurrentProcess(),
        &BaseAddress,
        &Size,
        NewProtect,
        OldProtect
    );

    KeUnstackDetachProcess(&ApcState);
    ObDereferenceObject(Process);
    return Status;
}

NTSTATUS CopyVirtualMemory(
    HANDLE SourceProcessId,
    PVOID SourceAddress,
    HANDLE TargetProcessId,
    PVOID TargetAddress,
    SIZE_T Size)
{
    PEPROCESS SourceProcess, TargetProcess;
    NTSTATUS Status;

    Status = PsLookupProcessByProcessId(SourceProcessId, &SourceProcess);
    if (!NT_SUCCESS(Status))
        return Status;

    Status = PsLookupProcessByProcessId(TargetProcessId, &TargetProcess);
    if (!NT_SUCCESS(Status))
    {
        ObDereferenceObject(SourceProcess);
        return Status;
    }

    SIZE_T Result;
    Status = MmCopyVirtualMemory(
        SourceProcess,
        SourceAddress,
        TargetProcess,
        TargetAddress,
        Size,
        KernelMode,
        &Result
    );

    ObDereferenceObject(SourceProcess);
    ObDereferenceObject(TargetProcess);
    return Status;
}

// 入口点调用
NTSTATUS CallKernelFunction(HANDLE ProcessId, PVOID EntryPoint, PVOID Context)
{
    PEPROCESS Process;
    NTSTATUS Status = PsLookupProcessByProcessId(ProcessId, &Process);
    if (!NT_SUCCESS(Status))
        return Status;

    HANDLE ThreadHandle;
    Status = PsCreateSystemThread(
        &ThreadHandle,
        THREAD_ALL_ACCESS,
        NULL,
        NULL,
        NULL,
        (PKSTART_ROUTINE)EntryPoint,
        Context
    );

    if (NT_SUCCESS(Status)) {
        ZwClose(ThreadHandle);
    }

    ObDereferenceObject(Process);
    return Status;
}

// 请求处理函数
NTSTATUS HandleDriverRequest(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);

    PIO_STACK_LOCATION Stack = IoGetCurrentIrpStackLocation(Irp);
    PVOID InputBuffer = NULL;
    PVOID OutputBuffer = NULL;
    ULONG InputBufferLength = 0;
    ULONG OutputBufferLength = 0;

    // 根据IRP的主功能代码处理不同类型的请求
    switch (Stack->MajorFunction)
    {
    case IRP_MJ_CREATE:
    case IRP_MJ_CLOSE:
        Irp->IoStatus.Status = STATUS_SUCCESS;
        Irp->IoStatus.Information = 0;
        break;

    case IRP_MJ_DEVICE_CONTROL:
    {
        InputBuffer = Irp->AssociatedIrp.SystemBuffer;
        OutputBuffer = Irp->AssociatedIrp.SystemBuffer;
        InputBufferLength = Stack->Parameters.DeviceIoControl.InputBufferLength;
        OutputBufferLength = Stack->Parameters.DeviceIoControl.OutputBufferLength;

        if (!InputBuffer || !OutputBuffer || !InputBufferLength || !OutputBufferLength)
        {
            Irp->IoStatus.Status = STATUS_INVALID_PARAMETER;
            break;
        }

        prequest_data Request = (prequest_data)InputBuffer;
        if (!Request)
        {
            Irp->IoStatus.Status = STATUS_INVALID_PARAMETER;
            break;
        }

        switch (Request->code)
        {
        case init_driver:
        {
            pdriver_init Init = (pdriver_init)Request->data;
            if (!Init)
            {
                Irp->IoStatus.Status = STATUS_INVALID_PARAMETER;
                break;
            }

            Init->init = true;
            Irp->IoStatus.Status = STATUS_SUCCESS;
            break;
        }
        case get_base:
        {
            pbase_request Base = (pbase_request)Request->data;
            if (!Base)
            {
                Irp->IoStatus.Status = STATUS_INVALID_PARAMETER;
                break;
            }

            PVOID BaseAddress;
            Irp->IoStatus.Status = GetModuleBase(Base->pid, Base->name, &BaseAddress);
            if (NT_SUCCESS(Irp->IoStatus.Status))
                Base->handle = BaseAddress;
            break;
        }
        case read_memory:
        {
            pread_request Read = (pread_request)Request->data;
            if (!Read)
            {
                Irp->IoStatus.Status = STATUS_INVALID_PARAMETER;
                break;
            }

            Irp->IoStatus.Status = ReadPhysicalMemory(Read->pid, Read->address, Read->buffer, Read->size);
            break;
        }
        case write_memory:
        {
            pwrite_request Write = (pwrite_request)Request->data;
            if (!Write)
            {
                Irp->IoStatus.Status = STATUS_INVALID_PARAMETER;
                break;
            }

            Irp->IoStatus.Status = WritePhysicalMemory(Write->pid, Write->address, Write->buffer, Write->size);
            break;
        }
        case protect_process:
        {
            process_request_t* ProcessRequest = (process_request_t*)Request->data;
            if (!ProcessRequest)
            {
                Irp->IoStatus.Status = STATUS_INVALID_PARAMETER;
                break;
            }

            Irp->IoStatus.Status = ProtectProcess((HANDLE)ProcessRequest->process_id);
            break;
        }
        case alloc_memory:
        {
            pallocate_request Alloc = (pallocate_request)Request->data;
            if (!Alloc)
            {
                Irp->IoStatus.Status = STATUS_INVALID_PARAMETER;
                break;
            }

            Irp->IoStatus.Status = AllocateVirtualMemory(
                Alloc->targetPid,
                &Alloc->targetAddress,
                Alloc->size,
                Alloc->allocationType,
                Alloc->protect
            );
            break;
        }
        case free_memory:
        {
            pfree_request Free = (pfree_request)Request->data;
            if (!Free)
            {
                Irp->IoStatus.Status = STATUS_INVALID_PARAMETER;
                break;
            }

            Irp->IoStatus.Status = FreeVirtualMemory(Free->targetPid, Free->address);
            break;
        }
        case protect_memory:
        {
            pprotect_request Protect = (pprotect_request)Request->data;
            if (!Protect)
            {
                Irp->IoStatus.Status = STATUS_INVALID_PARAMETER;
                break;
            }

            ULONG OldProtect;
            Irp->IoStatus.Status = ProtectVirtualMemory(
                Protect->targetPid,
                (PVOID)Protect->sourceAddress,
                Protect->size,
                Protect->protect,
                &OldProtect
            );
            break;
        }
        case copy_memory:
        {
            pcopy_request Copy = (pcopy_request)Request->data;
            if (!Copy)
            {
                Irp->IoStatus.Status = STATUS_INVALID_PARAMETER;
                break;
            }

            Irp->IoStatus.Status = CopyVirtualMemory(
                Copy->sourcePid,
                Copy->sourceAddress,
                Copy->targetPid,
                Copy->targetAddress,
                Copy->size
            );
            break;
        }
        case call_entry:
        {
            pcall_entry_request Call = (pcall_entry_request)Request->data;
            if (!Call)
            {
                Irp->IoStatus.Status = STATUS_INVALID_PARAMETER;
                break;
            }

            Irp->IoStatus.Status = CallKernelFunction(
                Call->process_id,
                Call->address,
                Call->shellcode
            );
            break;
        }
        default:
            Irp->IoStatus.Status = STATUS_INVALID_PARAMETER;
            break;
        }

        if (NT_SUCCESS(Irp->IoStatus.Status))
            Irp->IoStatus.Information = OutputBufferLength;
        break;
    }
    default:
        Irp->IoStatus.Status = STATUS_INVALID_DEVICE_REQUEST;
        Irp->IoStatus.Information = 0;
        break;
    }

    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return Irp->IoStatus.Status;
}