from pwn import * 

#64bit binay.
# repeated rdi+0x8 makes rdi-0x8 should same with 0x0 
# in take input 0x4009c9, make file named top_secret
# in  0x400a63, recv input to 0x6ccd60.
# if input aaaa, func 0x40eac0 make program exited. 
# func 0x40e990 take param 0x6CA0A0 -> 0x6cc160
# 0x43ed20 = exit . routine 0x40ea2c cmp rbp with 0x4be6e0
# in routine 0x40e9b1 , rbp+0x0 => r13(0x6cc160) = 0, 