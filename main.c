#include "main.h"

int main(int argc,char *argv[]){
    if(argc<3){
        printf("Usage: ./pe-shell.exe sourcefilepath targetfilepath\n");
    }
    if(add_shell(argv[1],argv[2])>0){
        printf(TEXT("Success.Shell was added.\n"));
    }else{
        printf("Fail.\n");
    }
}