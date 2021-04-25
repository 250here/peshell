#include "main.h"

int main(int argc,char *argv[]){
    if(argc<2){
        printf("Usage: ./pe-shell.exe filepath\n");
    }
    if(add_shell(argv[1])>0){
        printf("Success.\n");
    }else{
        printf("Fail.\n");
    }
}