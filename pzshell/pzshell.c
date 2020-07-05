#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <seccomp.h>
#include <linux/seccomp.h>
#include <sys/prctl.h>
#include <fcntl.h>

void sandbox(void)
{
	scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_ALLOW);

	if (ctx == NULL)
	{
		write(1, "seccomp error\n", 15);
		exit(-1);
	}

	seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(fork), 0);
	seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(vfork), 0);
	seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(clone), 0);
	seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(creat), 0);
	seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(ptrace), 0);
	seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(prctl), 0);
	seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(execve), 0);
	seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(execveat), 0);

	if (seccomp_load(ctx) < 0)
	{
		seccomp_release(ctx);
		write(1, "seccomp error\n", 15);
		exit(-2);
	}

	seccomp_release(ctx);
}

void Init(void)
{
	setvbuf(stdin, 0, 2, 0);
	setvbuf(stdout, 0, 2, 0);
	setvbuf(stderr, 0, 2, 0);
}

int main(void)
{
	char s[0x10];
	char result[0x100] = "\x0F\x05\x48\x31\xED\x48\x31\xE4\x48\x31\xC0\x48\x31\xDB\x48\x31\xC9\x48\x31\xF6\x48\x31\xFF\x4D\x31\xC0\x4D\x31\xC9\x4D\x31\xD2\x4D\x31\xDB\x4D\x31\xE4\x4D\x31\xED\x4D\x31\xF6\x4D\x31\xFF\x66\xbe\xf1\xde";
	char filter[2] = {'\x0f', '\x05'};

	Init();

	read(0, s, 8);

	for (int i = 0; i < 2; i ++)
	{
		if (strchr(s, filter[i]))
		{
			puts("filtering :)");
			exit(1);
		}
	}

	strcat(result, s);

	sandbox();

	(*(void (*)()) result + 2)();
}
