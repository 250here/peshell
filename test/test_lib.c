#include <stdio.h>
#include <windows.h>
BOOL APIENTRY DllMain( HMODULE hModule,DWORD  ul_reason_for_call,LPVOID lpReserved ){
    //while(1);
}
void show(){
    printf("shedllo world!");
}

__declspec(dllexport) void testShow(){
    show();
}