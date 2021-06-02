
#include "test.h"

void print_mem_c(PBYTE p){
    int i=0;
    for(i=0;i<0x180;i++){   
        char Ldr=*(PBYTE)((PBYTE)p+i*0x1);
        // printf("offset:0x%lx,Val:%c 0x%x\n",i,Ldr,Ldr);
        if(i%0x10==0){
            printf("\noffset:0x%lx,",i);
        }
        printf("%c",Ldr);
    }
    printf("\n");
}

void print_mem_d(PBYTE p){
    int i=0;
    for(i=0;i<0x180;i+=1){   
        DWORD Ldr=*(PDWORD)((PBYTE)p+i*0x1);
        printf("offset:0x%lx,Val:0x%lx\n",i,Ldr);
    }
}

PVOID getFunction_t(DWORD pKernel32DllBase,DWORD funcNameHash){
    //printf("%s\n",(PCHAR)pKernel32DllBase);
    PIMAGE_EXPORT_DIRECTORY pExportDir=(PIMAGE_EXPORT_DIRECTORY)(pKernel32DllBase+
        getNtHeaders(pKernel32DllBase)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
    DWORD funcNum=pExportDir->NumberOfFunctions;
    // printf("%d\n",funcNum);
    PCHAR* functionNames;
    functionNames=(PCHAR *)(pKernel32DllBase + pExportDir->AddressOfNames);
    DWORD* functionAddresses=(PDWORD)(pKernel32DllBase+pExportDir->AddressOfFunctions);
    PWORD functionsAddressNamesOfOriginal=(PWORD)(pKernel32DllBase+pExportDir->AddressOfNameOrdinals);
    //printf("%s\n",pExportDir->Name+(PBYTE)pKernel32DllBase);
    // printf("nameAd:%lx\n",pExportDir->AddressOfNames);
    // print_mem_c(*functionNames+pKernel32DllBase);
    DWORD index=0;
    char namebuf[1000];
    sprintf(namebuf,"./%s.funcHash.txt","user32.dll");
    FILE* f= fopen(namebuf,"w");
    for(;index<funcNum;index++){
        char buf[1000];
        sprintf(buf,"%s::%lx\n",functionNames[index]+pKernel32DllBase,RSHash(functionNames[index]+pKernel32DllBase,0));
        fwrite(buf,1,strlen(buf),f);
        if(RSHash(functionNames[index]+pKernel32DllBase,0)==funcNameHash){
            //printf(functionNames[index]+pKernel32DllBase);
            return (PVOID)(functionAddresses[functionsAddressNamesOfOriginal[index]]+pKernel32DllBase);
        }
    }
    //fflush(f);
    //fclose(f);
    return 0;
}

void jump(DWORD des){
    //asm("call des");
    int(*p)();
    p=(PVOID)des;
    p();
}

void printLog(){
    printf("0123789");
}

void str2hex(const char* str){
    int len=strlen(str);
    len=len%4==0?len:(len/4+1)*4;
    unsigned char buf[len];
    memset(buf,0,len);
    strcpy(buf,str);
    printf(buf);
    //printf("%ld",buf);
    for(int i=0;i<len/4;i++){
        printf(" 0x%lx ",*(PDWORD)(buf+i*4));
    }
    printf("\n");
}

int main(){
    // HMODULE base1=(HMODULE)getBaseAddresses();
    HMODULE base2=LoadLibrary("Kernelbase.dll");
    //printf("kernelbase.dll at:%lx",(DWORD)base2);

    // printf("%lx\n",(PBYTE)GetModuleHandle(NULL));
    PDWORD Teb = (PDWORD)NtCurrentTeb();                             //_TEB
    PDWORD Peb = *(PDWORD *)((PBYTE)Teb + 0x30);                     //PEB
    //print_mem_c((PBYTE)Peb);
    PDWORD Ldr = *(PDWORD *)((PBYTE)Peb + 0xc);                      //LDR_DATA_Addr
    LIST_ENTRY *pNode = (LIST_ENTRY *)*(PVOID *)((PBYTE)Ldr + 0x1c); //InInitializationOrderModuleList
    LIST_ENTRY *pNodeStart = pNode;
    //print_mem_c((PBYTE)pNode->Flink);
    //print_mem_d((PBYTE)pNode->Flink);
    while (pNode)
    {
        //printf(("%ls::%lx\n"),((PBYTE)pNode) + 0xd8,RSHash(((PBYTE)pNode) + 0xd8, 1));
        pNode = pNode->Flink;
        if (pNode == pNodeStart)
        {
            break;
        }
    }
    HMODULE kernel=LoadLibrary("kernel32.dll");
    //getFunction_t((DWORD)LoadLibrary("user32.dll"),0);
    // FARPROC(WINAPI *p)(HINSTANCE,LPSTR);
    //printf("val:%lx,expect:%lx",GetProcAddress(kernel,"VirtualProtect"),getFunction_t((DWORD)kernel,0x15d10e2e));

    //jump((DWORD)printLog);
    //str2hex("kernel32.dll");
    printf("%x\n",FindWindow(NULL,"test"));
    //str2hex("GetTickCount");
    
    // DWORD st[3];
    // st[0]=0x6e697270;
    // st[1]=0x6674;
    // st[2]=0x6c6c;
    // printf((char*)st);
    //stubRun();
}