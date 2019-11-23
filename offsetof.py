#! /usr/bin/env python3
import subprocess
import tempfile
import sys, os
import re

CC = os.environ.get('CC', 'cc')

class _TemplateGetter:
	def __init__(self, data, mode):
		self.data = data
		self.mode = mode

	def __getattr__(self, key):
		try:
			return self.data[self.mode, key]
		except KeyError:
			return self.data[key]

TPL = {}
TPL['header'] = '#include <%s>'

TPL['user', 'offset'] = 'PRINT_OFFSETOF(%s, %s);'
TPL['user', 'source'] = """
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

TPL['kernel', 'offset'] = 'offsetof(%s, %s),'
TPL['kernel', 'source'] = """
#include <linux/init.h>
#include <linux/module.h>
%s
MODULE_LICENSE("GPL");

size_t offsets[] = {
	%s
};
"""

MAKEFILE_DATA = """
ifneq ($(KERNELRELEASE),)
	obj-m := offsetof.o
else
	KERNELDIR ?= /lib/modules/$(shell uname -r)/build
	PWD := $(shell pwd)
default:
	make -C $(KERNELDIR) SUBDIRS=$(PWD) modules
endif
"""

def _run(*args):
	return subprocess.check_output(args).decode(sys.getfilesystemencoding())

def _get_symbols(fname):
	for line in _run('objdump', '-t', fname).split('\n'):
		match = re.match('^([0-9A-Fa-f]+) (.{7}) ([^ ]+)\t([0-9A-Fa-f]+) ([^ ]+)$', line)
		if match:
			start, flags, section, size, name = match.groups()
			yield int(start, 16), flags, section, int(size, 16), name

def _get_symbol(fname, name):
	symbol, = [info for info in _get_symbols(fname) if info[-1] == name]
	return symbol

def _get_source_data(headers, fields, mode):
	tpl = _TemplateGetter(TPL, mode)
	headers = [headers] if isinstance(headers, str) else headers
	header_lines = [tpl.header % header for header in headers]
	offset_lines = [tpl.offset % (struct, field) for struct, field in fields]
	return tpl.source % ('\n'.join(header_lines), '\n\t'.join(offset_lines))

def get_user_offsets(headers, fields):
	source_data = _get_source_data(headers, fields, 'user')

	with tempfile.TemporaryDirectory() as path:
		os.chdir(path)

		with open('offsetof.c', 'x') as f:
			f.write(source_data)

		_run(CC, 'offsetof.c', '-o', 'offsetof')
		for line in _run('./offsetof').rstrip('\n').split('\n'):
			struct, field, offset = line.rsplit(':')
			yield struct, field, int(offset)

def get_kernel_offsets(headers, fields):
	source_data = _get_source_data(headers, fields, 'kernel')

	with tempfile.TemporaryDirectory() as path:
		os.chdir(path)

		with open('Makefile', 'x') as f:
			f.write(MAKEFILE_DATA)

		with open('offsetof.c', 'x') as f:
			f.write(source_data)

		_run('make')

		start, flags, section, size, name = _get_symbol('offsetof.ko', 'offsets')
		# .bss if all the offsets are zero
		assert section in {'.data', '.bss'}, 'Expected variable to go to .data (or .bss) section, instead of %s - is everything ok?' % section

		itemsize, rem = divmod(size, len(fields))
		assert rem == 0, 'Expected array size to be divisible by field count'

		_run('objcopy', '-j', section, '-O', 'binary', 'offsetof.ko', 'offsetof.bin')

		with open('offsetof.bin', 'rb') as f:
			data = f.read()

		for i, (struct, field) in enumerate(fields):
			pos = start + i * itemsize
			yield struct, field, int.from_bytes(data[pos:pos+itemsize], sys.byteorder)

def get_offsets(headers, fields, kernel=False):
	return [get_user_offsets, get_kernel_offsets][kernel](headers, fields)

def main():
	from optparse import OptionParser

	parser = OptionParser(usage = 'usage: %prog [options] HEADER STRUCT FIELD...')
	parser.add_option('-k', '--kernel', dest='kernel', action='store_true', help='Query information about a kernel struct instead of a userspace struct')
	parser.set_defaults(kernel=False)

	opts, args = parser.parse_args()
	if len(args) < 3:
		parser.print_help()
		sys.exit(1)

	header, struct, *fields = args

	try:
		for struct, field, offset in get_offsets(header, [(struct, field) for field in fields], kernel=opts.kernel):
			print(field, offset)
	except subprocess.CalledProcessError as err:
		print('\nSTDOUT:\n' + err.output.decode('utf-8'), file=sys.stderr)
		raise

if __name__ == '__main__':
	main()

