
#include "test.h"

	
struct PEB
{
     UCHAR InheritedAddressSpace;
     UCHAR ReadImageFileExecOptions;
     UCHAR BeingDebugged;
     UCHAR BitField;
     ULONG ImageUsesLargePages: 1;
     ULONG IsProtectedProcess: 1;
     ULONG IsLegacyProcess: 1;
     ULONG IsImageDynamicallyRelocated: 1;
     ULONG SpareBits: 4;
     PVOID Mutant;
     PVOID ImageBaseAddress;
     DWORD Ldr;
} peb;


void print_mem(PBYTE p){
    int i=0;
    for(i=0;i<20;i++){   
        PDWORD Ldr=*(PDWORD*)((PBYTE)p+i*0x4);
        printf("offset:%lx,Val:%lx\n",i*4,Ldr);
    }
}

DWORD getKernal32Base()
{
    DWORD kernal32Base;



    
    //asm  ("push eax;mov  eax,fs:[0x30];mov  eax,[eax+0x0c];mov  esi,[eax+0x1c];lodsd;mov  eax,[eax+0x08];mov  kernal32Base,eax;pop  eax;");

    // __asm("pushq %eax");
    // __asm("movl  0x30(%fs),%eax");
    // __asm("movl  0x0c(%eax),%eax");
    // __asm("movl  0x1c(%eax),%esi");
    // __asm("lodsd");
    // __asm("movl  0x08(%eax),%eax");
    // __asm("movl  %eax,kernal32Base");
    // __asm("popq %eax");

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
    
    // printf("safe\n");
    // size_t**** val= (size_t ****)((PBYTE)NtCurrentTeb()+0x30);//__readfsdword(0x30);
    // printf("%x\n",val);
    // printf("%x\n",*(val+3));
    // kernal32Base=*(**(*(val + 3) + 3) + 2);


    printf("%lx\n",(DWORD)&(peb.Ldr)-(DWORD)&peb);
    printf("%lx\n",(PBYTE)GetModuleHandle(NULL));
    PDWORD Teb=(PDWORD)NtCurrentTeb();
    printf("%lx\n",Teb);
    PDWORD Peb = *(PDWORD*)((PBYTE)Teb+0x30);
    printf("%lx\n",Peb);
    
    PDWORD Ldr=*(PDWORD*)((PBYTE)Peb+0xc);
    printf("%lx\n",Ldr);

    print_mem((PBYTE)Ldr);

    // PDWORD Teb=(PDWORD)NtCurrentTeb();
    // PVOID64 Peb = (PBYTE)Teb + 0x30;
    // printf("%x\n",Teb);
    // printf("%x\n",*(Teb+0x40));
    // PVOID64 LDR_DATA_Addr = *(PVOID64**)((BYTE*)Peb+0x018);  //0x018是LDR相对于PEB偏移   存放着LDR的基地址
    // char* FullName; 
    // HMODULE hKernel32 = NULL;
    // LIST_ENTRY* pNode = NULL;
    // pNode =(LIST_ENTRY*)(*(PVOID64**)((BYTE*)LDR_DATA_Addr+0x30));  //偏移到InInitializationOrderModuleList
    // printf("safe\n");
    // while(1)
    // {
    //     FullName = (char*)((BYTE*)pNode+0x38);//BaseDllName基于InInitialzationOrderModuList的偏移
    //     if(*(FullName+12)=='\0')
    //     {
    //         hKernel32 = (HMODULE)(DWORD)(*((ULONG64*)((BYTE*)pNode+0x10)));//DllBase
    //         break;
    //     }
    //     pNode = pNode->Flink;
    // }

    return kernal32Base;
}

int main(){
    HMODULE base1=(HMODULE)getKernal32Base();
    HMODULE base2=LoadLibrary("Kernel32.dll");
    printf("val:%lx,expect:%lx",base1,base2);
}