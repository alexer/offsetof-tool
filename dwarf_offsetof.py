from elftools.elf.elffile import ELFFile

KIND2TAG = {
	'struct': 'DW_TAG_structure_type',
	'union': 'DW_TAG_union_type',
	'typedef': 'DW_TAG_typedef',
}

def get_offsets_from_ELF(filename, structs):
	# Do argument validation at the beginning, so that if there's a problem, we don't have to wait for the file to parse first
	names = []
	for struct in structs:
		kind, name = 'typedef', struct
		if ' ' in struct:
			kind, name = name.split(' ')
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

def main():
	import sys

	filename, struct = sys.argv[1:]

	for struct, field, offset in get_offsets_from_ELF(filename, [struct]):
		print(field, offset)

if __name__ == '__main__':
	main()

