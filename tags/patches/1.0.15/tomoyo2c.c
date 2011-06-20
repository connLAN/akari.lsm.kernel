/*
 * tomoyo2c.c
 *
 * Copyright (C) 2005-2011  NTT DATA CORPORATION
 *
 * This program converts policy for TOMOYO 1.8.x to C source.
 */
#include <stdio.h>

int main(int argc, char *argv[])
{
	_Bool newline = 0;
	int c;
	if (argc != 2) {
		fprintf(stderr, "%s name\n", argv[0]);
		return 1;
	}
	printf("static char ccs_builtin_%s[] __initdata =\n", argv[1]);
	putchar('"');
	while ((c = fgetc(stdin)) != EOF) {
		if (newline)
			putchar('"');
		newline = 0;
		if (c == '\\') {
			putchar('\\');
			putchar('\\');
		} else if (c == '"') {
			putchar('\\');
			putchar('"');
		} else if (c == '\n') {
			putchar('\\');
			putchar('n');
			putchar('"');
			putchar('\n');
			newline = 1;
		} else {
			putchar(c);
		}
	}
	if (!newline)
		putchar('"');
	putchar(';');
	putchar('\n');
	return 0;
}
