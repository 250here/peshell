echo "开始编译"
cd ./test
gcc test_exe.c -o test.exe
cd ..
gcc -shared -O0 -o stub.dll stub.c
gcc main.c pe_shell.c -o main.exe
echo "运行加壳工具"
./main.exe ./test/test.exe ./test_.exe
echo "运行加壳后测试程序"
./test_.exe

# gcc test.c stub.c -o test.exe
# ./test.exe
