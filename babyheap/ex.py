from pwn import * 

p = process ("./babyheap")

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
	
	mal(0x10,"a"*0x10)
	pause()
	mal(0x10,"b"*0x10)
	
	
	p.interactive()
