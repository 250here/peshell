#include "pe_shell.h"


FILE *pPeFile = NULL;
PBYTE pPeFileBuf = NULL;
DWORD fileSize = 0;

struct
{
    PBYTE pPe ;
    PIMAGE_DOS_HEADER pDosHeader ;
    PIMAGE_NT_HEADERS pNtHeader ;
} mPe;


struct
{
    DWORD oldbase;
    IMAGE_DATA_DIRECTORY IAT;
    IMAGE_DATA_DIRECTORY ROC;
    DWORD originalEntryPoint;
} peInfo;

struct
{
    PBYTE* dllTextSec;
    DWORD dllTextSecSize;
    DWORD runFuncAddress;
} mDll;

int add_shell(const char *filePath){
    if(open_PE_file(filePath)<0){
        return -1;
    }
    encryptTextSec();
    destroynTables();
    loadStubDll();
    saveNewPEFile(filePath);
    free(pPeFileBuf);
    free(mDll.dllTextSec);
}
int open_PE_file(const char *filePath){
    
    pPeFile=fopen(filePath,"rb");
    if(!pPeFile){
        printf("ERROR: Invalid file path.\n");
        return -1;
    }
    fseek(pPeFile,0,SEEK_END);
    fileSize=ftell(pPeFile);
    fseek(pPeFile,0,SEEK_SET);
    pPeFileBuf=malloc(fileSize+1);
    if(!pPeFileBuf){
        printf("ERROR: Molloc fail.\n");
        return -1;
    }
    fread(pPeFileBuf,fileSize,1,pPeFile);
    mPe.pDosHeader=(PIMAGE_DOS_HEADER)pPeFileBuf;
    if(check_PE()<0){
        printf("ERROR: not PE file.\n");
        return -1;
    }

    peInfo.originalEntryPoint=mPe.pNtHeader->OptionalHeader.AddressOfEntryPoint;
    peInfo.IAT=mPe.pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    peInfo.ROC=mPe.pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
    peInfo.oldbase=mPe.pNtHeader->OptionalHeader.ImageBase;



    fclose(pPeFile);
    return 1;
}


void loadStubDll(){
    char stubDllPath[]=".\\stub.dll";
    HMODULE stubModule=LoadLibrary(stubDllPath);
    DWORD pEntryFunc=(DWORD)GetProcAddress(stubModule,"stubRun");
    PIMAGE_NT_HEADERS dllNtHeaders=(PIMAGE_NT_HEADERS)(((PIMAGE_DOS_HEADER)stubModule)->e_lfanew+((DWORD)stubModule));
    // printf("safe\n");
    PIMAGE_SECTION_HEADER pTextSecHeader=IMAGE_FIRST_SECTION(dllNtHeaders);

    DWORD entryFuncVA=pEntryFunc-((DWORD)stubModule);
    //printf("Function stubRun VA:%lx\n",entryFuncVA);
    while(1){
        DWORD secStart=pTextSecHeader->VirtualAddress;
        if(secStart<=entryFuncVA&&entryFuncVA<secStart+pTextSecHeader->SizeOfRawData){
            break;
        }
        pTextSecHeader++;
    }
    printf("text Sec RVA:%lx,file offset:%lx\n",pTextSecHeader->VirtualAddress,pTextSecHeader->PointerToRawData);
    PBYTE* textSec=malloc(pTextSecHeader->SizeOfRawData);
    memcpy(textSec,((PBYTE)stubModule)+(pTextSecHeader->VirtualAddress),pTextSecHeader->SizeOfRawData);
    mDll.dllTextSecSize=pTextSecHeader->SizeOfRawData;
    mDll.dllTextSec=textSec;
    mDll.runFuncAddress=entryFuncVA-pTextSecHeader->VirtualAddress;
}

void destroynTables(){
    mPe.pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress=0;
    mPe.pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size=0;
    mPe.pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress=0;
    mPe.pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size=0;
    
    mPe.pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].VirtualAddress=0;
    mPe.pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].Size=0;
}

void encryptTextSec(){
    DWORD key=mPe.pNtHeader->FileHeader.TimeDateStamp;
    key=key^0x20210416;
    key=key^mPe.pNtHeader->OptionalHeader.AddressOfEntryPoint;
    printf("originKey:%lx;timestamp:%lx;eP:%lx\n",key,mPe.pNtHeader->FileHeader.TimeDateStamp,mPe.pNtHeader->OptionalHeader.AddressOfEntryPoint);
    
    DWORD entryPoint=mPe.pNtHeader->OptionalHeader.AddressOfEntryPoint;
    PIMAGE_SECTION_HEADER pTextSectionHeader=IMAGE_FIRST_SECTION(mPe.pNtHeader);
    while (1)
    {
        DWORD secStart=pTextSectionHeader->VirtualAddress;
        DWORD secEnd=pTextSectionHeader->VirtualAddress+pTextSectionHeader->SizeOfRawData;
        if(secStart<=entryPoint&&secEnd>=entryPoint){
            break;
        }
        pTextSectionHeader++;
    }
    DWORD start=pTextSectionHeader->PointerToRawData+(DWORD)pPeFileBuf;
    DWORD end=start+pTextSectionHeader->SizeOfRawData;
    //printf("textSize:0x%lx,startRVA:0x%lx\n",pTextSectionHeader->SizeOfRawData,pTextSectionHeader->VirtualAddress);
    PDWORD index=(PDWORD)start;
    for(;((DWORD)index)<=end-sizeof(DWORD);index++){
        if((DWORD)index-start<16){
            //printf("key%d:0x%lx,text:0x%lx\n",(DWORD)index-start,key,*index);
        }
        if((DWORD)index==end-sizeof(DWORD)){
            //   printf("last key0x%lx:0x%lx,text:0x%lx\n",(DWORD)index-start,key,*index);
        }
        DWORD newkey=*index^key;
        *index=(*index)^key;
        key=newkey;
    }
}

int check_PE(){
    if(fileSize<sizeof(IMAGE_DOS_HEADER)){
        printf("ERROR: Invalid file.Too small.\n");
        return -1;
    }
    if(mPe.pDosHeader->e_magic != IMAGE_DOS_SIGNATURE){
        printf("ERROR: Invalid file.Invalid dos signature MZ.\n");
        return -1;
    }
    if(mPe.pDosHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS) > fileSize){
        printf("ERROR: Invalid file.Too small.\n");
        return -1;
    }
    mPe.pNtHeader=(PIMAGE_NT_HEADERS)(pPeFileBuf + mPe.pDosHeader->e_lfanew);
    //printf("%lx,%lx\n",mPe.pDosHeader->e_lfanew,mPe.pNtHeader->Signature);
    //printf("%x %x %x\n",*(char*)(pPeFileBuf+0x74),*(char*)((DWORD)pPeFileBuf+0x75),*(char*)((DWORD)pPeFileBuf+0x76));
    if(mPe.pNtHeader->Signature != IMAGE_NT_SIGNATURE){
        printf("ERROR: Invalid file.Invalid NT signature .\n");
        return -1;
    }
    //printf("v Size:%lx\n",mPe.pNtHeader->OptionalHeader.SizeOfImage);
    return 1;
}

#define ALIGNIT(ALIG,NUM) ((NUM)%(ALIG)==0?(NUM):((NUM)/(ALIG)+1)*(ALIG))
void saveNewPEFile(const char *originalFilePath){
    char fname[_MAX_FNAME];  
    char ext[_MAX_EXT];
    _splitpath(originalFilePath,NULL,NULL,fname,ext);
    char newfilepath[_MAX_FNAME+_MAX_EXT+16];
    sprintf(newfilepath,("./%s_%s"),fname,ext);
    
    PIMAGE_SECTION_HEADER pFirstSectionHeader=IMAGE_FIRST_SECTION(mPe.pNtHeader);
    WORD secNum=mPe.pNtHeader->FileHeader.NumberOfSections;
    PIMAGE_SECTION_HEADER pLastSectionHeader=pFirstSectionHeader+secNum-1;
    
    DWORD sectionsEnd=pLastSectionHeader->PointerToRawData+pLastSectionHeader->SizeOfRawData;
    DWORD sectionsEndVA=pLastSectionHeader->VirtualAddress+ALIGNIT(mPe.pNtHeader->OptionalHeader.SectionAlignment,pLastSectionHeader->SizeOfRawData);
    printf("sections end fileoffSet:%lx,sections end VA:%lx,file end:%lx\n",sectionsEnd,sectionsEndVA,fileSize);

    DWORD newSectionSize=ALIGNIT(mPe.pNtHeader->OptionalHeader.FileAlignment ,mDll.dllTextSecSize);

    IMAGE_SECTION_HEADER newSection={0};
    newSection.Characteristics=0x60000020;
    char secName[IMAGE_SIZEOF_SHORT_NAME]=".stub";
    memcpy(newSection.Name,secName,IMAGE_SIZEOF_SHORT_NAME);
    newSection.PointerToRawData=sectionsEnd;
    newSection.SizeOfRawData=newSectionSize;
    newSection.VirtualAddress=sectionsEndVA;
    newSection.Misc.VirtualSize=mDll.dllTextSecSize;
    *(pLastSectionHeader+1)=newSection;

    memcpy(pPeFileBuf+sizeof(IMAGE_DOS_SIGNATURE),&peInfo,sizeof(peInfo));
    printf("Peinfo at:0x%x\n",0+sizeof(IMAGE_DOS_SIGNATURE));

    mPe.pNtHeader->OptionalHeader.SizeOfImage+=ALIGNIT((mPe.pNtHeader->OptionalHeader.SectionAlignment ), (mDll.dllTextSecSize));
    mPe.pNtHeader->FileHeader.NumberOfSections+=1;
    mPe.pNtHeader->OptionalHeader.AddressOfEntryPoint=newSection.VirtualAddress+mDll.runFuncAddress;

    DWORD newPeFileSize=fileSize+newSectionSize;
    PBYTE newPeBuf=malloc(newPeFileSize);
    memset(newPeBuf,0,newPeFileSize);
    memcpy(newPeBuf,pPeFileBuf,sectionsEnd);
    memcpy(newPeBuf+sectionsEnd,mDll.dllTextSec,mDll.dllTextSecSize);
    memcpy(newPeBuf+sectionsEnd+newSection.SizeOfRawData,pPeFileBuf+sectionsEnd,fileSize-sectionsEnd);

    FILE *newPeFile=fopen(newfilepath,"wb");
    fwrite(newPeBuf,1,newPeFileSize,newPeFile);

    free(newPeBuf);
}