#ifndef _PE_STUB_H
#define _PE_STUB_H

#include <windows.h>

__declspec(dllexport) int stubRun();


DWORD getKernal32Base();
#endif