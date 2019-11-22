#! /usr/bin/env python3
import subprocess
import tempfile
import sys, os
import re

CC = os.environ.get('CC', 'cc')

OFFSET_TPL = 'PRINT_OFFSETOF(%s, %s);'
SOURCE_TPL = """
#include <stdio.h>
#include <stddef.h>
#include <%s>

#define PRINT_OFFSETOF(STRUCT, FIELD) printf(#FIELD " %%zd\\n", offsetof(STRUCT, FIELD))

int main(void)
{
	%s
	return 0;
}
"""

def _run(*args):
	return subprocess.check_output(args).decode(sys.getfilesystemencoding())

def get_offsets(header, struct, fields):
	offset_lines = [OFFSET_TPL % (struct, field) for field in fields]
	source_data = SOURCE_TPL % (header, '\n\t'.join(offset_lines))

	with tempfile.TemporaryDirectory() as path:
		os.chdir(path)

		with open('offsetof.c', 'x') as f:
			f.write(source_data)

		_run(CC, 'offsetof.c', '-o', 'offsetof')
		for line in _run('./offsetof').rstrip('\n').split('\n'):
			field, offset = line.split()
			yield field, int(offset)

def main():
	header, struct, *fields = sys.argv[1:]

	try:
		for field, offset in get_offsets(header, struct, fields):
			print(field, offset)
	except subprocess.CalledProcessError as err:
		print('\nSTDOUT:\n' + err.output.decode('utf-8'), file=sys.stderr)
		raise

if __name__ == '__main__':
	main()

