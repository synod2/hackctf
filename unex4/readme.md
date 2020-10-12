nav_journal write up
---------------
pwn , 473pts

desc 
---------------

- FSB
- FSOP


files 
---------------

- challenge 
- libc.so.6(glibc 2.23->ubuntu 16.04)
- ld-2.23.so

checksec 
---------------
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX disabled
    PIE:      No PIE (0x400000)
    RWX:      Has RWX segments
solution 
---------------
프로그램 실행시 fgets로 44바이트 입력받는다. 








