#! /usr/bin/env python3
import subprocess
import tempfile
import sys, os
import re

CC = os.environ.get('CC', 'cc')

HEADER_TPL = '#include <%s>'
OFFSET_TPL = 'PRINT_OFFSETOF(%s, %s);'
SOURCE_TPL = """
#include <stdio.h>
#include <stddef.h>
%s

#define PRINT_OFFSETOF(STRUCT, FIELD) printf(#STRUCT ":" #FIELD ":%%zd\\n", offsetof(STRUCT, FIELD))

int main(void)
{
	%s
	return 0;
}
"""

def _run(*args):
	return subprocess.check_output(args).decode(sys.getfilesystemencoding())

def get_offsets(headers, fields):
	headers = [headers] if isinstance(headers, str) else headers
	header_lines = [HEADER_TPL % header for header in headers]
	offset_lines = [OFFSET_TPL % (struct, field) for struct, field in fields]
	source_data = SOURCE_TPL % ('\n'.join(header_lines), '\n\t'.join(offset_lines))

	with tempfile.TemporaryDirectory() as path:
		os.chdir(path)

		with open('offsetof.c', 'x') as f:
			f.write(source_data)

		_run(CC, 'offsetof.c', '-o', 'offsetof')
		for line in _run('./offsetof').rstrip('\n').split('\n'):
			struct, field, offset = line.rsplit(':')
			yield struct, field, int(offset)

def main():
	header, struct, *fields = sys.argv[1:]

	try:
		for struct, field, offset in get_offsets(header, [(struct, field) for field in fields]):
			print(field, offset)
	except subprocess.CalledProcessError as err:
		print('\nSTDOUT:\n' + err.output.decode('utf-8'), file=sys.stderr)
		raise

if __name__ == '__main__':
	main()

