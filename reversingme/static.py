st = ""

st += "1617181926381617919194"
res = ""

for i in range(0,0x16) : 
	print(hex(ord(st[21-i])))
	if i % 2 == 0 : 
		res += chr((ord(st[21-i]) ^ 0xc) - 4)
	else : 
		res += chr((ord(st[21-i]) ^ 0xc) + 4)

print(res)

