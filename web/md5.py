import hashlib
 
#string = raw_input()

md5 = hashlib.new('md5')
sha = hashlib.sha1("10932435112")
print sha.hexdigest()
# for i in range(0,1000000) : 
# 	string = str(i)
# 	sha = hashlib.sha1(string)
# 	#sha.update(string)
# 	res = sha.hexdigest()
# 	if "0e" in res[:2] : 
# 		if res[2:].isdigit() : 
# 			print str(i)+" : "+res