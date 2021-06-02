echo "开始编译"
cd ./test
gcc -shared -O0 -o test_lib.dll test_lib.c
gcc test_dll.c -o test_main.exe
cd ..
gcc -shared -O0 -o stub.dll stub.c
gcc main.c pe_shell.c -o main.exe
echo "加壳加壳工具"
# ./main.exe ./main.exe ./main_.exe
./main.exe ./test/test_lib.dll ./test/test_lib_.dll
echo "运行加壳后测试程序"
./test/test_main.exe
