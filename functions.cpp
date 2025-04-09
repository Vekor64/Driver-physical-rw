#include "functions.h"
#include "comms.h"

NTSTATUS ReadPhysicalMemory(HANDLE ProcessId, PVOID SourceAddress, PVOID TargetAddress, SIZE_T Size)
{
    PEPROCESS SourceProcess;
    NTSTATUS Status = PsLookupProcessByProcessId(ProcessId, &SourceProcess);
    if (!NT_SUCCESS(Status))
        return Status;

    SIZE_T Result;
    Status = MmCopyVirtualMemory(
        SourceProcess,
        SourceAddress,
        PsGetCurrentProcess(),
        TargetAddress,
        Size,
        KernelMode,
        &Result
    );

    ObDereferenceObject(SourceProcess);
    return Status;
}

NTSTATUS WritePhysicalMemory(HANDLE ProcessId, PVOID TargetAddress, PVOID SourceAddress, SIZE_T Size)
{
    PEPROCESS TargetProcess;
    NTSTATUS Status = PsLookupProcessByProcessId(ProcessId, &TargetProcess);
    if (!NT_SUCCESS(Status))
        return Status;

    SIZE_T Result;
    Status = MmCopyVirtualMemory(
        PsGetCurrentProcess(),
        SourceAddress,
        TargetProcess,
        TargetAddress,
        Size,
        KernelMode,
        &Result
    );

    ObDereferenceObject(TargetProcess);
    return Status;
}

NTSTATUS ProtectProcess(HANDLE ProcessId)
{
    PEPROCESS Process;
    NTSTATUS Status = PsLookupProcessByProcessId(ProcessId, &Process);
    if (!NT_SUCCESS(Status))
        return Status;

    PUCHAR ProcessObject = (PUCHAR)Process;

    *(PUCHAR)(ProcessObject + 0x87A) = 1;

    ObDereferenceObject(Process);
    return STATUS_SUCCESS;
}

NTSTATUS GetModuleBase(HANDLE ProcessId, LPCSTR ModuleName, PVOID* BaseAddress)
{
    if (!ProcessId || !ModuleName || !BaseAddress)
        return STATUS_INVALID_PARAMETER;

    *BaseAddress = NULL;
    
    PEPROCESS Process;
    NTSTATUS Status = PsLookupProcessByProcessId(ProcessId, &Process);
    if (!NT_SUCCESS(Status))
        return Status;

    __try {
        KAPC_STATE ApcState;
        KeStackAttachProcess(Process, &ApcState);

        PPEB Peb = PsGetProcessPeb(Process);
        if (!Peb) {
            KeUnstackDetachProcess(&ApcState);
            ObDereferenceObject(Process);
            return STATUS_UNSUCCESSFUL;
        }

        if (!Peb->Ldr) {
            KeUnstackDetachProcess(&ApcState);
            ObDereferenceObject(Process);
            return STATUS_UNSUCCESSFUL;
        }

        PPEB_LDR_DATA Ldr = Peb->Ldr;
        PLIST_ENTRY ModuleList = &Ldr->InLoadOrderModuleList;
        PLIST_ENTRY Entry = ModuleList->Flink;

        while (Entry && Entry != ModuleList) {
            PLDR_DATA_TABLE_ENTRY Module = CONTAINING_RECORD(Entry, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
            if (Module && Module->BaseDllName.Buffer && Module->BaseDllName.Length > 0) {
                char ModuleNameBuffer[256];
                ULONG ConvertedLength;
                Status = RtlUnicodeToMultiByteN(
                    ModuleNameBuffer,
                    sizeof(ModuleNameBuffer) - 1,
                    &ConvertedLength,
                    Module->BaseDllName.Buffer,
                    Module->BaseDllName.Length
                );

                if (NT_SUCCESS(Status)) {
                    ModuleNameBuffer[ConvertedLength] = '\0';
                    if (_stricmp(ModuleNameBuffer, ModuleName) == 0) {
                        *BaseAddress = Module->DllBase;
                        KeUnstackDetachProcess(&ApcState);
                        ObDereferenceObject(Process);
                        return STATUS_SUCCESS;
                    }
                }
            }
            Entry = Entry->Flink;
        }

        KeUnstackDetachProcess(&ApcState);
    }
    __except(EXCEPTION_EXECUTE_HANDLER) {
        Status = GetExceptionCode();
    }

    ObDereferenceObject(Process);
    return Status != STATUS_SUCCESS ? Status : STATUS_NOT_FOUND;
}

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