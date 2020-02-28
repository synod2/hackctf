#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
	
void Init(void)
{
	setvbuf(stdin, 0, 2, 0);
	setvbuf(stdout, 0, 2, 0);
	setvbuf(stderr, 0, 2, 0);
}

int main(void)
{
	Init();

	char result[100] = "\x0F\x05\x48\x31\xED\x48\x31\xE4\x48\x31\xC0\x48\x31\xDB\x48\x31\xC9\x48\x31\xD2\x48\x31\xF6\x48\x31\xFF\x4D\x31\xC0\x4D\x31\xC9\x4D\x31\xD2\x4D\x31\xDB\x4D\x31\xE4\x4D\x31\xED\x4D\x31\xF6\x4D\x31\xFF";
	char shellcode[30];
	char filter[4] = {'\xb0', '\x3b', '\x0f', '\x05'};

	read(0, shellcode, 30);
	

	for (int i = 0; i <= 3; i ++)
	{
		if (strchr(shellcode, filter[i]))
		{
			puts("filtering :)");
			exit(1);
		}		
	}

	for (int i = 0; i < 30; i++)
	{
		if (!shellcode[i])
		{
			puts("null :)");
			exit(1);
		}
	}

	strcat(result, shellcode);
	(*(void (*)()) result + 2)();
}
