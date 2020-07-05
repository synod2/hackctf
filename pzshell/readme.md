### Hackctf - pzshell

#### checksec 
- nx disable, PIE/Canary enabled, RELRO FULL 
 

input 8 byte shellcode. 

filtering 0x0f, 0x05 => syscall asm command . 

input shellcode will be added after result-shellcode.

and sandbox function has seccomp - it will blocked fork , vfork, clone, creat, ptrace, prctl, execve, execveat. 

how can bypass seccomp? 

at first, what is this shellcode?

>   0:   0f 05                   syscall 
   2:   48 31 ed                xor    rbp,rbp
   5:   48 31 e4                xor    rsp,rsp
   8:   48 31 c0                xor    rax,rax
   b:   48 31 db                xor    rbx,rbx
   e:   48 31 c9                xor    rcx,rcx
  11:   48 31 f6                xor    rsi,rsi
  14:   48 31 ff                xor    rdi,rdi
  17:   4d 31 c0                xor    r8,r8
  1a:   4d 31 c9                xor    r9,r9
  1d:   4d 31 d2                xor    r10,r10
  20:   4d 31 db                xor    r11,r11
  23:   4d 31 e4                xor    r12,r12
  26:   4d 31 ed                xor    r13,r13
  29:   4d 31 f6                xor    r14,r14
  2c:   4d 31 ff                xor    r15,r15
  2f:   66 be f1 de             mov    si,0xdef1

shellcode started with syscall. and clear all registers. except rdx register.

at last, si has 0xdef1. what is mean? 

how to solving this? for using what? 

1. problem has disannounced about libc, it didnt using libc addr. 
2. syscall at first. using this for syscall
3. 0xdef1 has moved to si. using this for calc something. 
4. seccomp func filtering many things.. 
5. rdx didnt cleared. using this registers value. -> rdx-0x2 = syscall address. 
6. input into stack, and NX is disabled. 

how about input more bytes into stack? 

for trying this, using rdx and rip's values, and rsi values. 

- read function - rax:0 , rdi:0 , rsi:addr, rdx:bytes

1. xor rsi with rdx - find some stack space
2. jump rdx (not call)
3. so, we can input?? 

but, xor is not always successful. add will be fail, sub is impossible. 

using xchg command. it will change register's value. so, try again 

1. sub 0x2 to rdx
2. xchg rdx,rsi
3. jmp rsi 

```
    sc = asm('sub dl,0x2')
    sc += asm('xchg rsi,rdx')
    sc += asm('jmp rsi')
```

if it ended, we can call read function. (but send code in same time.)

so, we can input more than 8 bytes. 

lets get dir info-> get file name -> open file -> read file -> write file 

how to get dir info? using getdents function. 

- getdents - rax :0x4e, rdi : fd , rsi : ret dirent structure addr 

get fd from open function. 

- open - rax:0x2 , rdi: filename, rsi: flag, rdx : mode 

we need to input filename "." , 0x2e + nop code. 

dirent struct has dir's file names. so lets find it. 

```
    

```





