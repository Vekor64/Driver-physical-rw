# Driver-physical-rw
Driver using IOCTL for some cheat, with physical read and write

## functions
```cpp
ReadPhysicalMemory();
WritePhysicalMemory();
ProtectProcess();
GetModuleBase();
AllocateVirtualMemory();
FreeVirtualMemory();
ProtectVirtualMemory();
CopyVirtualMemory();
```

## Application calling function
```cpp
bool __fastcall SendRequest(void* data, request_codes code)
{
    if (!data || !code || hDriver == INVALID_HANDLE_VALUE)
    {
        return false;
    }

    request_data request{ 0 };
    request.unique = request_unique;
    request.data = data;
    request.code = code;
    DWORD bytesReturned = 0;

    BOOL success = DeviceIoControl(
        hDriver,
        static_cast<DWORD>(code),
        &request,
        sizeof(request_data),
        &request,
        sizeof(request_data),
        &bytesReturned,
        NULL
    );

    if (!success)
        return false;

    return true;
}
```
