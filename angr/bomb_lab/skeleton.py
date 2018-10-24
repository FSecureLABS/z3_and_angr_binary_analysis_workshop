import angr

def phase_one(p, base):
	pass

def phase_two(p, base):
	pass

def phase_three(p, base):
	pass

def phase_four(p, base):
	"""
	If you have a big array of memory you want splitting into individual integers, this might help: 
	#Convert to little endian and flip args as they'll have read out backwards
	args = []
	for i in range(20):
		val = (answer >> 8 * 4 * i) & 0xFFFFFFFF
		out = struct.unpack('<I', struct.pack('>I', val))[0]
		args.append(str(out))
	args.reverse()
	print(' '.join(args))
	"""
	pass	

def phase_five(p, base):
	pass

def phase_six(p, base):
	pass

if __name__ == "__main__":
	p = angr.Project('bomb',load_options={"auto_load_libs":False})
	base = p.loader.main_object.min_addr
	print("Phase one:")
	phase_one(p, base)
	print("Phase two:")
	phase_two(p, base)
	print("Phase three:")
	phase_three(p, base)
	print("Phase four:")
	phase_four(p, base)
	print("Phase five:")
	phase_five(p, base)
	print("Phase six:")
	phase_six(p, base)
