import angr
import binascii
import struct

# Make command line output look pretty
import logging
logging.getLogger('angr.state_plugins.symbolic_memory').setLevel('ERROR')
logging.getLogger('pyvex.lifting.libvex').setLevel('WARNING')

def phase_one(p, base):
	# Phase one expects a single string argument, I assume this is passed in rdi 
	# and then symbolically execute from the start of the function to it's return,
	# avoid calls to boom
	state = p.factory.blank_state(addr=base + 0xa1c)

	sm = p.factory.simulation_manager(state)
	sm.explore(find=base + 0xf5d, avoid= base + 0x133b)
	try:
		found = sm.found[0]
		memory = found.memory.load(found.regs.rdi, 128)
		answer = found.solver.eval(memory, cast_to=bytes)
		out = answer[:answer.index(b'\x00')]
		print("Hex output: 0x{}".format(out.hex()))
		print("Raw string output: {}".format(out))
	except:
		print('failed to find required input')

def phase_two(p, base):
	# Phase two expects three string arguments, so we position
	# them in the amd64 argument registers and then symbolically execute as before
	state = p.factory.blank_state(addr=base + 0xb22)

	arg_one = state.solver.BVS('arg_one', 8 * 128)
	arg_one_addr = 0x0000000041414141
	state.memory.store(arg_one_addr, arg_one)
	state.add_constraints(state.regs.rdi == arg_one_addr)
	arg_two = state.solver.BVS('arg_two', 8 * 128)
	arg_two_addr = 0x0000000042424242
	state.memory.store(arg_two_addr, arg_two)
	state.add_constraints(state.regs.rsi == arg_two_addr)
	arg_three = state.solver.BVS('arg_three', 8 * 128)
	arg_three_addr = 0x0000000043434343
	state.memory.store(arg_three_addr, arg_three)
	state.add_constraints(state.regs.rdx == arg_three_addr)
	sm = p.factory.simulation_manager(state)
	sm.explore(find=base + 0xf5d, avoid= base + 0x133b)
	found = sm.found[0]
	hex_args = []
	str_args = []
	answer = found.solver.eval(arg_one, cast_to=bytes)
	out = answer[:answer.index(b'\x00')]
	hex_args.append("0x{}".format(out.hex()))
	str_args.append(out)
	answer = found.solver.eval(arg_two, cast_to=bytes)
	out = answer[:answer.index(b'\x00')]
	hex_args.append("0x{}".format(out.hex()))
	str_args.append(out)
	answer = found.solver.eval(arg_three, cast_to=bytes)
	out = answer[:answer.index(b'\x00')]
	hex_args.append("0x{}".format(out.hex()))
	str_args.append(out)
	print("hex arguments: {}".format(' '.join(hex_args)))
	print("Raw string arguments: {}".format(str_args))

def phase_three(p, base):
	# Phase three expects four 32 bit integer arguments, so we load 32 bit symbolic variables
	# into the first four argument registers and continue as before

	state = p.factory.blank_state(addr=base + 0xbe0)

	arg_one = state.solver.BVS('arg_one', 8 * 4)
	state.regs.rdi = arg_one
	arg_two = state.solver.BVS('arg_two', 8 * 4)
	state.regs.rsi = arg_two
	arg_three = state.solver.BVS('arg_three', 8 * 4)
	state.regs.rdx = arg_three
	arg_four = state.solver.BVS('arg_four', 8 * 4)
	state.regs.rcx = arg_four
	sm = p.factory.simulation_manager(state)
	sm.explore(find=base + 0xf5d, avoid= base + 0x133b)
	found = sm.found[0]
	out = ''
	answer = found.solver.eval(arg_one)
	out += str(answer) + ' '
	answer = found.solver.eval(arg_two)
	out += str(answer) + ' '
	answer = found.solver.eval(arg_three)
	out += str(answer) + ' '
	answer = found.solver.eval(arg_four)
	out += str(answer) + ' '
	print("Solution: {}".format(out))

def phase_four(p, base):
	# Phase four expects an array of integers
	# So we create a large block of symbolic memory and then pass a pointer
	# to it as the first argument
	state = p.factory.blank_state(addr=base + 0xc82)

	arg_one = state.solver.BVS('arg_one', 8 * 4 * 20)
	arg_one_addr = 0x0000000041414141
	state.memory.store(arg_one_addr, arg_one)
	state.add_constraints(state.regs.rdi == arg_one_addr)
	sm = p.factory.simulation_manager(state)
	sm.explore(find=base + 0xf5d, avoid= base + 0x133b)
	found = sm.found[0]
	out = ''
	# Once the array values have been found, we can parse it's contents to break it out into
	# indvidual integer arguments
	answer = found.solver.eval(arg_one)
	#Convert to little endian and flip args as they'll have read out backwards
	args = []
	for i in range(20):
		val = (answer >> 8 * 4 * i) & 0xFFFFFFFF
		out = struct.unpack('<I', struct.pack('>I', val))[0]
		args.append(str(out))
	args.reverse()
	print(' '.join(args))

def phase_five(p, base):
	# Phase five has the same requirements as four and the code is almost identical
	state = p.factory.blank_state(addr=base + 0xd1f)

	arg_one = state.solver.BVS('arg_one', 8 * 4 * 20)
	arg_one_addr = 0x0000000041414141
	state.memory.store(arg_one_addr, arg_one)
	state.add_constraints(state.regs.rdi == arg_one_addr)
	sm = p.factory.simulation_manager(state)
	sm.explore(find=base + 0xf5d, avoid= base + 0x133b)
	found = sm.found[0]
	out = ''
	answer = found.solver.eval(arg_one)
	#Convert to little endian and flip args as they'll have read out backwards
	args = []
	for i in range(20):
		val = (answer >> 8 * 4 * i) & 0xFFFFFFFF
		out = struct.unpack('<I', struct.pack('>I', val))[0]
		args.append(str(out))
	args.reverse()
	print(' '.join(args))

def phase_six(p, base):
	# Phase six does some basic string manipulation, this is easy to load and solve in Angr
	# But takes by far the longest time to run due to the complex constraints
	state = p.factory.blank_state(addr=base + 0xd9e)

	arg_one = state.solver.BVS('arg_one', 8 * 20)
	arg_one_addr = 0x0000000041414141
	state.memory.store(arg_one_addr, arg_one)
	state.add_constraints(state.regs.rdi == arg_one_addr)
	sm = p.factory.simulation_manager(state)
	sm.explore(find=base + 0xf5d, avoid= base + 0x133b, enable_veritesting=True)
	found = sm.found[0]
	answer = found.solver.eval(arg_one, cast_to=bytes)
	print(answer)

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
