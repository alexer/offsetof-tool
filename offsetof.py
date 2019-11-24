#! /usr/bin/env python3
import subprocess
import tempfile
import sys, os
import re

try:
	from elftools.elf.elffile import ELFFile
	_has_elftools = True
except ImportError as err:
	_has_elftools = False
	_elftools_error = err

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

TPL['offset'] = '%s %s;'
TPL['user-elf', 'source'] = """
#include <stdio.h>
#include <stddef.h>
%s

struct {
	%s
} offsets;

int main(void)
{
	return 0;
}
"""
TPL['kernel-elf', 'source'] = """
#include <linux/init.h>
#include <linux/module.h>
%s
MODULE_LICENSE("GPL");

struct {
	%s
} offsets;
"""

MAKEFILE_DATA = """
CC += -g
ifneq ($(KERNELRELEASE),)
	obj-m := offsetof.o
else
	KERNELDIR ?= /lib/modules/$(shell uname -r)/build
	PWD := $(shell pwd)
default:
	make -C $(KERNELDIR) SUBDIRS=$(PWD) modules
endif
"""

KIND2TAG = {
	'struct': 'DW_TAG_structure_type',
	'union': 'DW_TAG_union_type',
	'typedef': 'DW_TAG_typedef',
}

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

def _validate_chars(value, extra, error):
	try:
		value.encode('ascii')
	except UnicodeEncodeError:
		valid = False
	else:
		value = ''.join(set(value) - set(extra))
		valid = value.isalnum()
	if not valid:
		raise ValueError(error)

def _validate_hpath(value):
	_validate_chars(value, '_{}[]#()<%:;.?*+-/^&|~!=,"', 'Invalid header path')

def _validate_id(value):
	_validate_chars(value, '_', 'Invalid C identifier')

def _validate_struct(struct):
	kind, name = 'typedef', struct
	if ' ' in struct:
		kind, name = struct.split(' ', 1)
		if kind not in {'struct', 'union'}:
			raise ValueError('Not a struct or union')
	_validate_id(name)
	return kind, name

def _validate_fields(values):
	for struct, field in values:
		_validate_struct(struct)
		_validate_id(field)

def _get_source_data(headers, fields, mode):
	_validate_hpath(headers)
	_validate_fields(fields)
	tpl = _TemplateGetter(TPL, mode)
	headers = [headers] if isinstance(headers, str) else headers
	header_lines = [tpl.header % header for header in headers]
	offset_lines = [tpl.offset % (struct, field) for struct, field in fields]
	return tpl.source % ('\n'.join(header_lines), '\n\t'.join(offset_lines))

def get_all_offsets_from_ELF(filename, structs):
	# Do argument validation at the beginning, so that if there's a problem, we don't have to wait for the file to parse first
	names = []
	for struct in structs:
		kind, name = _validate_struct(struct)
		names.append((KIND2TAG[kind], name.encode('ascii')))

	with open(filename, 'rb') as f:
		elffile = ELFFile(f)

		dwarf = elffile.get_dwarf_info()
		items = get_items_from_DWARF(dwarf, names=set(names))
		cus = {cu for cu, item in items.values()}
		cu2offset2die = {cu: {die.offset: die for die in cu.iter_DIEs()} for cu in cus}
		for struct, (kind, value) in zip(structs, names):
			cu, item = items[kind, value]
			offset2die = cu2offset2die[cu]
			if kind == 'typedef':
				item = offset2die[item.attributes['DW_AT_type'].value]
			for field, offset in get_offsets_from_DIE(item, offset2die):
				yield struct, field, offset

def get_given_offsets_from_ELF(filename, fields):
	_validate_fields(fields)
	structs = {struct for struct, field in fields}
	fields = set(fields)
	for struct, field, offset in get_all_offsets_from_ELF(filename, structs):
		if (struct, field) in fields:
			yield struct, field, offset

def find_item_from_DWARF(dwarf, tag, name):
	items = get_items_from_DWARF(dwarf, names={(tag, name)})
	if items:
		item, = items.values()
		return item

def get_items_from_DWARF(dwarf, tags=None, names=None):
	assert bool(tags) != bool(names), 'Must give either tags or names (but not both)'
	if names:
		tags = {tag for tag, name in names}

	found = {}
	for cu in dwarf.iter_CUs():
		die = cu.get_top_DIE()
		for child in die.iter_children():
			if child.tag not in tags:
				continue
			attr = child.attributes.get('DW_AT_name')
			if attr is None:
				continue
			name = (child.tag, attr.value)
			if names is None or name in names:
				assert name not in found, 'Duplicate DWARF item'
				found[name] = (cu, child)
	return found

def get_offsets_from_DIE(die, offset2die, start=0):
	assert die.tag in {'DW_TAG_structure_type', 'DW_TAG_union_type'}, 'Unhandled main type: ' + die.tag
	# Union members all start at the same offset (at least I sure fucking hope so)
	offset = start
	for child in die.iter_children():
		assert child.tag == 'DW_TAG_member', 'Unhandled child type: ' + child.tag
		if die.tag == 'DW_TAG_structure_type':
			# Struct members have different starting offsets
			offset = start + child.attributes['DW_AT_data_member_location'].value
		else:
			assert 'DW_AT_data_member_location' not in child.attributes, 'Union members can have starting offsets?!'

		if 'DW_AT_name' in child.attributes:
			yield child.attributes['DW_AT_name'].value.decode('ascii'), offset
		else:
			# Anonymous union or struct
			child_type = offset2die[child.attributes['DW_AT_type'].value]
			yield from get_offsets_from_DIE(child_type, offset2die, offset)

def get_given_user_offsets(headers, fields):
	source_data = _get_source_data(headers, fields, 'user')

	with tempfile.TemporaryDirectory() as path:
		os.chdir(path)

		with open('offsetof.c', 'x') as f:
			f.write(source_data)

		_run(CC, 'offsetof.c', '-o', 'offsetof')
		for line in _run('./offsetof').rstrip('\n').split('\n'):
			struct, field, offset = line.rsplit(':')
			yield struct, field, int(offset)

def get_given_kernel_offsets(headers, fields):
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

def get_all_offsets_elftools(headers, structs, kernel=False):
	fields = [(struct, 'f%d' % i) for i, struct in enumerate(structs)]
	source_data = _get_source_data(headers, fields, ['user', 'kernel'][kernel] + '-elf')

	with tempfile.TemporaryDirectory() as path:
		os.chdir(path)

		with open('offsetof.c', 'x') as f:
			f.write(source_data)

		if kernel:
			with open('Makefile', 'x') as f:
				f.write(MAKEFILE_DATA)

			_run('make')
		else:
			_run(CC, '-g', 'offsetof.c', '-o', 'offsetof.ko')

		yield from get_all_offsets_from_ELF('offsetof.ko', structs)

def get_given_offsets_elftools(headers, fields, kernel=False):
	_validate_fields(fields)
	structs = {struct for struct, field in fields}
	fields = set(fields)
	for struct, field, offset in get_all_offsets_elftools(headers, list(structs), kernel):
		if (struct, field) in fields:
			yield struct, field, offset

def get_given_offsets(headers, fields, kernel=False):
	if _has_elftools:
		return get_given_offsets_elftools(headers, fields, kernel)
	else:
		return [get_given_user_offsets, get_given_kernel_offsets][kernel](headers, fields)

def get_all_offsets(headers, structs, kernel=False):
	if _has_elftools:
		return get_all_offsets_elftools(headers, structs, kernel)
	else:
		raise RuntimeError('Either install elftools, or specify fields explicitly / use get_given_offsets()') from _elftools_error

def main():
	from optparse import OptionParser

	parser = OptionParser(usage='usage: %prog [options] HEADER|ELF STRUCT [FIELD...]')
	parser.add_option('-k', '--kernel', dest='kernel', action='store_true', help='Query information about a kernel struct instead of a userspace struct')
	parser.set_defaults(kernel=False)

	opts, args = parser.parse_args()
	if len(args) < 2:
		parser.print_help()
		sys.exit(1)

	header, struct, *fields = args
	if os.path.exists(header):
		with open(header, 'rb') as f:
			is_elf = f.read(4) == b'\x7fELF'
	else:
		is_elf = False

	kwargs = dict(kernel=opts.kernel) if not is_elf else {}
	if fields:
		get_offsets = [get_given_offsets, get_given_offsets_from_ELF][is_elf]
		fields = [(struct, field) for field in fields]
	else:
		get_offsets = [get_all_offsets, get_all_offsets_from_ELF][is_elf]
		fields = [struct]

	try:
		for struct, field, offset in get_offsets(header, fields, **kwargs):
			print(field, offset)
	except subprocess.CalledProcessError as err:
		print('\nSTDOUT:\n' + err.output.decode('utf-8'), file=sys.stderr)
		raise

if __name__ == '__main__':
	main()

