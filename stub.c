#include "stub.h"

#pragma comment(linker, "/merge:.data=.text")
#pragma comment(linker, "/merge:.rdata=.text")
#pragma comment(linker, "/section:.text,RWE")



__declspec(dllexport) int stubRun()
{
    struct PEINFO* pPeInfo;
    DWORD kernel32Base=0;
    DWORD pEbase=0;
    struct FUNCTION_TABLE funcTable;
    pPeInfo=(struct PEINFO*)(pEbase+sizeof(IMAGE_DOS_SIGNATURE));
    getBaseAddresses(&kernel32Base,&pEbase);
    funcTable.funcGetProcAddress=getFunction(kernel32Base,0x65eaeaf6);
    funcTable.funcLoadlibraryA=getFunction(kernel32Base,0xbf0c7d2);
    funcTable.funcGetModuleHandleA=getFunction(kernel32Base,0x2f8c088b);
    funcTable.funcVirtualAlloc=getFunction(kernel32Base,0x23e765e4);
    funcTable.funcVirtualProtect=getFunction(kernel32Base,0x15d10e2e);

    decryptTextSection(&funcTable,pEbase,pPeInfo);

    return 0;
}

//RSHash
unsigned int RSHash(char *str, int isWide)
{
    unsigned int b = 378551;
    unsigned int a = 63689;
    unsigned int hash = 0;
    if (isWide)
    {
        PWCHAR pstr = (PWCHAR)str;
        while (*pstr)
        {
            hash = hash * a + (*pstr++);
            a *= b;
        }
    }
    else
    {
        while (*str)
        {
            hash = hash * a + (*str++);
            a *= b;
        }
    }
    return (hash & 0x7FFFFFFF);
}

void getBaseAddresses(PDWORD pKernelDllBase,PDWORD pPEBase)
{
    DWORD kernal32Base = 0;

    //asm  ("push eax;mov  eax,fs:[0x30];mov  eax,[eax+0x0c];mov  esi,[eax+0x1c];lodsd;mov  eax,[eax+0x08];mov  kernal32Base,eax;pop  eax;");

    // __asm
    // {
    //     push eax
    //     mov  eax,fs:[0x30]
    //     mov  eax,[eax+0x0c]
    //     mov  esi,[eax+0x1c]
    //     lodsd
    //     mov  eax,[eax+0x08]
    //     mov  kernal32Base,eax
    //     pop  eax
    // }

    // size_t**** val= (size_t ****)(PBYTE)NtCurrentTeb()+0x30;//__readfsdword(0x30);
    // kernal32Base=*(**(*(val + 3) + 7) + 2);

    PDWORD Teb = (PDWORD)NtCurrentTeb();                             //_TEB
    PDWORD Peb = *(PDWORD *)((PBYTE)Teb + 0x30);                     //PEB

    PDWORD Base = *(PDWORD *)((PBYTE)Peb + 0x8);
    *pPEBase=(DWORD)Base;

    PDWORD Ldr = *(PDWORD *)((PBYTE)Peb + 0xc);                      //LDR_DATA_Addr
    LIST_ENTRY *pNode = (LIST_ENTRY *)*(PVOID *)((PBYTE)Ldr + 0x1c); //InInitializationOrderModuleList
    LIST_ENTRY *pNodeStart = pNode;
    while (pNode)
    {
        if (RSHash(((PBYTE)pNode) + 0xd8, 1) == 0x4426cf5c)
        {
            kernal32Base = *(PDWORD)((PBYTE)pNode + 0x70);
            break;
        }
        pNode = pNode->Flink;
        if (pNode == pNodeStart)
        {
            break;
        }
    }

    *pKernelDllBase= kernal32Base;
}

PIMAGE_NT_HEADERS getNtHeaders(DWORD pPEbase){
    return (PIMAGE_NT_HEADERS)(((PIMAGE_DOS_HEADER)pPEbase)->e_lfanew+pPEbase);
}




PVOID getFunction(DWORD pKernel32DllBase,DWORD funcNameHash){
    PIMAGE_EXPORT_DIRECTORY pExportDir=(PIMAGE_EXPORT_DIRECTORY)(pKernel32DllBase+
        getNtHeaders(pKernel32DllBase)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
    DWORD funcNum=pExportDir->NumberOfFunctions;
    PCHAR* functionNames;
    functionNames=(PCHAR *)(pKernel32DllBase + pExportDir->AddressOfNames);
    DWORD* functionAddresses=(PDWORD)(pKernel32DllBase+pExportDir->AddressOfFunctions);
    PWORD functionsAddressNamesOfOriginal=(PWORD)(pKernel32DllBase+pExportDir->AddressOfNameOrdinals);
    DWORD index=0;
    for(;index<funcNum;index++){
        if(RSHash(functionNames[index]+pKernel32DllBase,0)==funcNameHash){
            return (PVOID)(functionAddresses[functionsAddressNamesOfOriginal[index]]+pKernel32DllBase);
        }
    }
    return 0;
}
void decryptTextSection(struct FUNCTION_TABLE* funcTable,DWORD peBase,struct PEINFO* peInfo){
    PIMAGE_NT_HEADERS pNtHeaders=getNtHeaders(peBase);
    DWORD key=pNtHeaders->FileHeader.TimeDateStamp;
    key=key^0x20210416;
    key=key^peInfo->originalEntryPoint;
    
}
