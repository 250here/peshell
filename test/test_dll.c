#include<windows.h>

int main(){
    HMODULE dllBase= LoadLibrary("kernel32.dll");
    // while(dllBase);
    FreeLibrary(dllBase);
    dllBase= LoadLibrary("./test_lib_.dll");
    // while(dllBase);
    void(* show)(void)=(PVOID)GetProcAddress(dllBase,"testShow");
    show();
    FreeLibrary(dllBase);
}