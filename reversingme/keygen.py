from pwn import * 

def encode(inp,v2) : 
	return ((inp+12)*v2 + 17) % 70 + 48

ans = "OO]oUU2U<sU2UsUsK"
rea = "OO]oUU2U<sU2UsUsK"
res = ""
tres = ""
v2 = 72
slen = 18 

for i in range(0,16) : 
	#print(str(ord(ans[i]))+":"),
	for j in range(33,127) : 
		tres = encode(j,v2)
		if tres == ord(ans[i]) : 
		#	res += chr(j)
		#	print(chr(j)+"("+str(j)+")")
			# break
			if i==0 : 
				res += 'd'
				tres = encode(100,v2)
				print(tres)
				print(encode(65,v2))
				break
			# 	tres = encode(100,v2)
			# 	print(chr(100)+"("+str(100)+")")
			# 	break
			else :
				res += chr(j)
			# 	print(chr(j)+"("+str(j)+")")
			 	break
	v2 = tres
print("\nres : "+res+" len : "+str(len(res)))

#p = process("./keygen")
p = remote("ctf.j0n9hyun.xyz",9004)
context.log_level = 'debug'
p.recvuntil(":")
p.send(res)
p.interactive()

