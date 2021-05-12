#ifndef _PE_STUB_H
#define _PE_STUB_H

#include <windows.h>
#include <stdio.h>

struct PEINFO
{
    DWORD oldbase;
    IMAGE_DATA_DIRECTORY IAT;
    IMAGE_DATA_DIRECTORY ROC;
    DWORD originalEntryPoint;
};

struct FUNCTION_TABLE
{
    PVOID funcGetProcAddress;
    PVOID funcLoadlibraryA;
    PVOID funcVirtualProtect;
    PVOID funcGetModuleHandleA;
    PVOID funcVirtualAlloc;
};

struct HASHCHAINNODE
{
    PVOID nextFuncAddr;
    DWORD lastFuncHash;
};

__declspec(dllexport) int stubRun();

unsigned int RSHash(char *str,int isWide);
void getBaseAddresses();
PVOID getFunction(DWORD pKernel32DllBase,DWORD funcNameHash);
__declspec(dllexport) DWORD decryptTextSection(struct FUNCTION_TABLE* funcTable,DWORD peBase,struct PEINFO* peInfo);
void getfunctions(struct FUNCTION_TABLE* funcTable,DWORD kernel32Base);
__declspec(dllexport) DWORD fixROC(struct FUNCTION_TABLE* funcTable,DWORD peBase,struct PEINFO* pPeInfo);
PIMAGE_NT_HEADERS getNtHeaders(DWORD pPEbase);
__declspec(dllexport) DWORD fixIAT(struct FUNCTION_TABLE* funcTable,DWORD peBase,struct PEINFO* pPeInfo);
__declspec(dllexport) void antiDebug(struct FUNCTION_TABLE* funcTable,DWORD peBase,struct PEINFO* pPeInfo,DWORD pKernel32DllBase);

#endif