#ifndef _PE_SHELL_H
#define _PE_SHELL_H

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>



int add_shell(const char *filePath,const char* targetFilePath);
int open_PE_file(const char *filePath);
int check_PE();
void encryptTextSec();
void destroynTables();
void loadStubDll();
void saveNewPEFile(const char *filePath);

#endif
