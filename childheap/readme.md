childheap
---------------
pwn

desc 
---------------

- double free bug
- got overwrite 

files 
---------------
- childheap
- libc.so.6(glibc 2.23->ubuntu 16.04)


checksec 
---------------
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)

solution 
---------------
이름처럼 힙문제. 실행하면 malloc 메뉴와 free 메뉴 두개만 있다.
입력 가능한 인덱스 범위는 0~4, 바이트는 최대 128바이트이고 입력한 숫자만큼만 데이터를 입력할 수 있다.

view 메뉴는 존재하지 않으므로 leak을위해선 별도의 작업이 필요해보이고,
RELRO가 partial이므로 got overwrite를 통해 leak 작업을 해야될듯 하다. 

malloc시에 같은 인덱스에 연속해서 할당을 시도하면 새로 메모리를 할당한다. 


free시에 값의 초기화는 이뤄지지 않는다. 
할당되지 않은 인덱스나 이미 해제된 인덱스에 대해서는 free시 검사가 이뤄지지 않는다.
그러나 더블프리시에는 에러가 발생한다. 1-2-1로 더블프리 체크를 우회해보자. 

바꿀만한 함수를 찾아보면 input_number 함수 내부의 atoi 함수정도가 있는데, 인자로 전해지는게 
스택영역의 buf 변수다. 해당 함수를 printf 함수로 바꾸어 fsb를 일으켜 출력해보는 방식을 생각해 볼 수 있겠는데,
입력 가능한 문자열이 최대 2글자밖에 안되므로 힘들어보인다.

```
0x602000:       0x0000000000601e28      0x00007fdcaeb24168
0x602010:       0x00007fdcae914ee0      0x00007fdcae5b74f0
0x602020:       0x00007fdcae5a2690      0x0000000000400716
0x602030:       0x00007fdcae5a96b0      0x00007fdcae588800
0x602040:       0x00007fdcae62a250      0x00007fdcae553740
0x602050:       0x00007fdcae5b7130      0x00007fdcae5a2e70
0x602060:       0x00007fdcae569e80      0x00007fdcae59e4d0

0000000000602018 R_X86_64_JUMP_SLOT  free@GLIBC_2.2.5
0000000000602020 R_X86_64_JUMP_SLOT  puts@GLIBC_2.2.5
0000000000602028 R_X86_64_JUMP_SLOT  __stack_chk_fail@GLIBC_2.4
0000000000602030 R_X86_64_JUMP_SLOT  setbuf@GLIBC_2.2.5
0000000000602038 R_X86_64_JUMP_SLOT  printf@GLIBC_2.2.5
0000000000602040 R_X86_64_JUMP_SLOT  read@GLIBC_2.2.5
0000000000602048 R_X86_64_JUMP_SLOT  __libc_start_main@GLIBC_2.2.5
0000000000602050 R_X86_64_JUMP_SLOT  malloc@GLIBC_2.2.5
0000000000602058 R_X86_64_JUMP_SLOT  setvbuf@GLIBC_2.2.5
0000000000602060 R_X86_64_JUMP_SLOT  atoi@GLIBC_2.2.5
0000000000602068 R_X86_64_JUMP_SLOT  __isoc99_scanf@GLIBC_2.7
0000000000602070 R_X86_64_JUMP_SLOT  exit@GLIBC_2.2.5

```
free후 malloc시 유효한 위치인지 체크할때 청크의 사이즈를 체크하는데, 
이 사이즈는 4바이트 단위로 체크하므로, got테이블에서 4바이트 단위로 끊기는 주소들 중 덮어씌워도 문제없을만한 것들을 찾아보면 
2000 위치의 60으로 시작하는 주소와 2028위치의 40으로 시작하는 주소, 2038 위치의 마지막 바이트가 00이므로
그 다음의 2040위치의 7f 주소를 써먹어볼 수 있겠다. 
2028 위치 이후에는 setbuf, printf, read 함수가 있는데 printf를 printf로 바꿀수는 없으므로 이건 안되겠다.
2000을 사용하면 2018의 free 함수 got를 덮어씌울 수 있을것 같고, free함수는 호출될때 인자로 스택의 주소를 ㅡ가지고 오므로
이를 사용하면 될것같다. 

```
gdb-peda$ x/10gx 0x602018-30
0x601ffa:       0x1e28000000000000      0x4168000000000060
0x60200a:       0x4ee000007fdcaeb2      0x74f000007fdcae91
0x60201a:       0x269000007fdcae5b      0x071600007fdcae5a
```
바이트수를 잘 계산해서 60을 청크 사이즈에 위치시키고, free의 got영역을 덮도록 하면 된다.

그다음 더블프리를 이용해 원하는 주소를 덮어씌우는 동작부터 해보자. 
128바이트짜리 메모리를 할당 해제하여 unsorted bin에 올려두면 fd와 bk에 libc의 주소가 올라간다.
그다음 free의 got를 printf로 덮어씌우고, 아까 할당 해제한 메모리를 free 하면 해당 메모리의 주소가 출력된다. 
해당 주소는 main_arena+88 위치이므로 오프셋을 계산하면 libc 주소를 얻을 수 있다. 

이렇게 libc 주소를 얻었고, 다른 함수(exit같은)의 got를 원샷 가젯으로 덮어씌우면 되겠다.
got 테이블을 다시 확인해보면 남은건 2028이후의 printf와 2040이후의 malloc을 쓰거나, 
malloc_hook 함수를 덮어씌워봐도 되긴 한다. 
7f를 덮어야 하므로 70크기의 메모리에 대해 더블프리를 발생시키는 코드를 작성하는데
libc leak 전에 미리 더블프리를 만들어놓아야 이후에 프리 없이도 오버라이트를 진행할 수 있다. 
하나 문제가 발생할수도 있는게, 이렇게 하면 read함수의 got도 망가질 수 있다. 
그러나 read함수 자리에 read함수의 주소를 다시 덮어주면 문제가 안된다. 
그 뒤의 libc_start_main 도 덮어주고, malloc함수를 호출하되 가젯 조건에 맞게끔 size를 0 으로 입력해주면 쉘이 떨어진다.












