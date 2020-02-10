#include <stdio.h>

int main(){
	char *str = "OfdlDSA|3tXb32~X3tX@sX`4tXtz";
	
	int key=0;
	for(int i=0;i<=28;i++){
		
	//	key = (key+1) ^ 0x7;
		printf("%c",str[i]^7);
	}
//	printf("%s",str);
	
	
/*	
OfdlDSA|3tXb32~X3tX@sX`4tXtz

0x1이랑 0x17을 바꾸면서 반복

check 함수 - key 에 들어갈 수 있는 값은 7 아니면 0 
*/
	
}