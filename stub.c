#include "stub.h"


#pragma comment(linker,"/merge:.data=.text")
#pragma comment(linker,"/merge:.rdata=.text")
#pragma comment(linker,"/section:.text,RWE")

struct PEINFO
{
    DWORD oldbase;
    IMAGE_DATA_DIRECTORY IAT;
    IMAGE_DATA_DIRECTORY ROC;
    DWORD originalEntryPoint;
} peInfo;

__declspec(dllexport) int stubRun()
{

    int a = 0x12345678;
    while (1);
    return *(char *)0;
}

DWORD getKernal32Base()
{
    DWORD kernal32Base;



    
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
    
    
    size_t**** val= (size_t ****)(PBYTE)NtCurrentTeb()+0x30;//__readfsdword(0x30);
    kernal32Base=*(**(*(val + 3) + 7) + 2);

    return kernal32Base;
}