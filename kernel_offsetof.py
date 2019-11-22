#! /usr/bin/env python3
import subprocess
import tempfile
import sys, os
import re

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

OFFSET_TPL = 'offsetof(%s, %s),'
SOURCE_TPL = """
#include <linux/init.h>
#include <linux/module.h>
#include <%s>
MODULE_LICENSE("GPL");

size_t offsets[] = {
	%s
};
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

def get_offsets(header, struct, fields):
	offset_lines = [OFFSET_TPL % (struct, field) for field in fields]
	source_data = SOURCE_TPL % (header, '\n\t'.join(offset_lines))

	with tempfile.TemporaryDirectory() as path:
		os.chdir(path)

		with open('Makefile', 'x') as f:
			f.write(MAKEFILE_DATA)

		with open('offsetof.c', 'x') as f:
			f.write(source_data)

		_run('make')

		start, flags, section, size, name = _get_symbol('offsetof.ko', 'offsets')
		assert section == '.data', 'Expected variable to go to .data section, instead of %s - is everything ok?' % section

		itemsize, rem = divmod(size, len(fields))
		assert rem == 0, 'Expected array size to be divisible by field count'

		_run('objcopy', '-j', section, '-O', 'binary', 'offsetof.ko', 'offsetof.bin')

		with open('offsetof.bin', 'rb') as f:
			data = f.read()

		for i, field in enumerate(fields):
			pos = start + i * itemsize
			yield field, int.from_bytes(data[pos:pos+itemsize], sys.byteorder)

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

