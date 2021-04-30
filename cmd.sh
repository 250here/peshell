cd ./test
gcc test_main.c -o test.exe
cd ..
gcc -shared -O0 -o stub.dll stub.c
gcc main.c pe_shell.c -o main.exe
./main.exe ./test/test.exe
./test_.exe

# gcc test.c stub.c -o test.exe
# ./test.exe
