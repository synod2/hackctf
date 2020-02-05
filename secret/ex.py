from pwn import * 

p = process("./j0n9hyun_secret")

#64bit binary , canary off, nx on, pie off, relro partial 

#main func 0x400ce4 , getting input at 0x400a63 call 0x40f500 func. location 0x6ccd60(heap) 
#open file -> read (6CCD6A)-> write -> close 
#after, call another func.
#when connect at remote, 
#j0n9hyun is very otaku
#https://ctf.j0n9hyun.xyz/404_page 

