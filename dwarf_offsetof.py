from elftools.elf.elffile import ELFFile

KIND2TAG = {
	'struct': 'DW_TAG_structure_type',
	'union': 'DW_TAG_union_type',
	'typedef': 'DW_TAG_typedef',
}

def get_offsets_from_ELF(filename, struct):
	kind, name = 'typedef', struct
	if ' ' in name:
		kind, name = struct.split(' ')
	tag = KIND2TAG[kind]
	with open(filename, 'rb') as f:
		elffile = ELFFile(f)

		dwarf = elffile.get_dwarf_info()
		item_cu, item_die = find_item_from_DWARF(dwarf, tag, name.encode('ascii'))
		offset2die = {die.offset: die for die in item_cu.iter_DIEs()}
		if kind == 'typedef':
			item_die = offset2die[item_die.attributes['DW_AT_type'].value]
		yield from get_offsets_from_DIE(item_die, offset2die)

def find_item_from_DWARF(dwarf, tag, name):
	for cu in dwarf.iter_CUs():
		die = cu.get_top_DIE()
		for child in die.iter_children():
			if child.tag != tag:
				continue
			attr = child.attributes.get('DW_AT_name')
			if attr is None:
				continue
			if attr.value == name:
				return cu, child

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

def main():
	import sys

	filename, struct = sys.argv[1:]

	for field, offset in get_offsets_from_ELF(filename, struct):
		print(field, offset)

if __name__ == '__main__':
	main()

