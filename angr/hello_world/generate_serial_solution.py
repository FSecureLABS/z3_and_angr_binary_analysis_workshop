import angr
import binascii

# Make command line output look pretty
import logging
logging.getLogger('cle.loader').setLevel('ERROR')
logging.getLogger('angr.engines.successors').setLevel('ERROR')
logging.getLogger('angr.state_plugins.symbolic_memory').setLevel('ERROR')

# Generate valid argument for 'valid_serial_one'
def solve_one(base):
	# Load the project - we don't want to load any imported libraries, 
	# Instead using angr's shortcut methods
	p = angr.Project('serial.o', load_options={'auto_load_libs':False})
	# We don't want any pre-existing state, starting execution at the 
	# beginning of the method, with only the library resources in memory
	state = p.factory.blank_state(addr=base + 0x7d0)
	# Create a simulation manager based on the blank state - 
	# allowing us to use the symbolic execution APIs
	sm = p.factory.simulation_manager(state)
	# We want to reach the end of the function but avoid the 'reject' function
	sm.explore(find=base + 0x801, avoid=base + 0xaf5)
	# We can access the paths through the binary that have been explored using symbolic execution
	# Using sm.explore will cause angr to symbolically execute until a path reaches the target address
	# Or all paths have deadended or errorer. We assume it's found a solution here and access the state
	# for the first path which found the target address. 
	found = sm.found[0]
	# It's a 64 bit binary so the first argument is passed in the rdi register
	# Since the code hasn't written over the register contents at the end of the 
	# function a pointer to the argument is still in rdi
	# Here we are loading 128 bytes of symbolic memory from the address held in rdi
	memory = found.memory.load(found.regs.rdi, 128)
	# Now we need to evaluate the constraints which represent the memory we just loaded
	answer = found.solver.eval(memory, cast_to=bytes)
	# At this point answer should hold a potential input which would avoid triggering
	# the reject function, we don't want to print everything as we'll get some junk bytes
	# so we only take up to the end of the NULL terminated cstring
	out = answer[:answer.index(b'\x00')]
	# Print the output as hexidecimal and then as an ascii string
	print("Hex output: 0x{}".format(out.hex()))
	print("Raw string output: {}".format(out))

# Generate valid argument for 'valid_serial_two'
def solve_two(base):
	p = angr.Project('serial.o', load_options={'auto_load_libs':False})
	state = p.factory.blank_state(addr=base + 0x802)
	# Instead of just assuming the key will be in rdi, we can explicitly create the
	# symbolic memory for it and directly reference it as a variable
	arg = state.solver.BVS('serial', 8 * 128)
	# Place the symbolic variable at a specific address
	rand_addr = 0x0000000041414141
	state.memory.store(rand_addr, arg)
	# And then make rdi hold a pointer to it as the first argument
	state.add_constraints(state.regs.rdi == rand_addr)
	# Then symbolically execute from the function start to its return as previously
	sm = p.factory.simulation_manager(state)
	sm.explore(find=base + 0x870, avoid=base + 0xaf5)
	found = sm.found[0]
	answer = found.solver.eval(arg, cast_to=bytes)
	out = answer[:answer.index(b'\x00')]
	print("Hex output: 0x{}".format(out.hex()))
	print("Raw string output: {}".format(out))

# Generate valid argument for 'valid_serial_three'
def solve_three(base):
	# Mostly the same before
	p = angr.Project('serial.o', load_options={'auto_load_libs':False})
	state = p.factory.blank_state(addr=base + 0x871)
	arg = state.solver.BVS('serial', 8 * 128)

	rand_addr = 0x0000000041414141
	state.memory.store(rand_addr, arg)
	state.add_constraints(state.regs.rdi == rand_addr)
	
	sm = p.factory.simulation_manager(state)
	# Veritesting is a technique for identifying merge points in software that is being symbolically executed, 
	# this helps combat the 'path explosion' issue
	# Originally described in the following paper: https://users.ece.cmu.edu/~dbrumley/pdf/Avgerinos%20et%20al._2014_Enhancing%20Symbolic%20Execution%20with%20Veritesting.pdf 
	sm.explore(find=base + 0x921, avoid=base + 0xaf5, enable_veritesting=True)
	found = sm.found[0]
	answer = found.solver.eval(arg, cast_to=bytes)
	out = answer[:answer.index(b'\x00')]
	print("Hex output: 0x{}".format(out.hex()))
	print("Raw string output: {}".format(out))

# Generate valid argument for 'valid_serial_four'
def solve_four():
	p = angr.Project('serial.o', load_options={'auto_load_libs':False})
	base = p.loader.main_object.min_addr

	state = p.factory.blank_state(addr=base + 0x922)
	arg = state.solver.BVS('serial', 8 * 128)
	rand_addr = 0x0000000041414141
	state.memory.store(rand_addr, arg)
	state.add_constraints(state.regs.rdi == rand_addr)
	sm = p.factory.simulation_manager(state)
	sm.explore(find=base + 0xa10, avoid=base + 0xaf5, enable_veritesting=True)	
	found = sm.found[0]
	# Sometmes we want to generate multiple possible solutions, this can be done by evaluating
	# a possible value for a variable and then adding an additional constraint that the result can't 
	# be that value and re-evaluating
	seen = set()
	while len(seen) < 3:
		# Evaluate one possible solution
		answer = found.solver.eval(arg, cast_to=bytes)
		out = answer[:answer.index(b'\x00')]
		if out not in seen:
			print('Valid serial:')
			print("\tHex output: 0x{}".format(out.hex()))
			print("\tRaw string output: {}".format(out))
			seen.add(out)
		# Add an additional constraint to get an alternative solution
		found.solver.add(arg != answer)

# Generate valid argument for 'valid_serial_combo'
def solve_combo():
	# This problem is similar to the previous one but the function expects multiple arguments
	p = angr.Project('serial.o', load_options={'auto_load_libs':False})
	base = p.loader.main_object.min_addr

	state = p.factory.blank_state(addr=base + 0xa11)
	
	# The calling convention for x64 code specfies that arguments from right to left are
	# passed in rdi then rsi then rdx then rcx etc 
	# So we create two symbolic memory regions, place them both in memory and then make rdi and rsi 
	# point to them 
	arg_one = state.solver.BVS('serial_one', 8 * 128)
	arg_two = state.solver.BVS('serial_two', 8 * 128)
	addr_one = 0x0000000041414141
	addr_two = 0x0000000042424242
	state.memory.store(addr_one, arg_one)
	state.memory.store(addr_two, arg_two)
	state.add_constraints(state.regs.rdi == addr_one)
	state.add_constraints(state.regs.rsi == addr_two)
	sm = p.factory.simulation_manager(state)
	sm.explore(find=base + 0xaf4, avoid=base + 0xaf5, enable_veritesting=True)
	found = sm.found[0]
	# Get potential values for both arguments
	answer_one = found.solver.eval(arg_one, cast_to=bytes)
	answer_two = found.solver.eval(arg_two, cast_to=bytes)
	answer_one_trim = answer_one[:answer_one.index(b'\x00')]
	answer_two_trim = answer_two[:answer_two.index(b'\x00')]
	print("Hex output one: 0x{}, Hex output two: 0x{}".format(answer_one_trim.hex(), answer_two_trim.hex()))
	print("Raw string outputs, one: {}, two: {}".format(answer_one_trim, answer_two_trim))

if __name__ == "__main__":
	base = 0x400000
	print('Solving valid_serial_one')
	solve_one(base)
	print('Solving valid_serial_two')
	solve_two(base)
	print('Solving valid_serial_three')
	solve_three(base)
	print('Solving valid_serial_four')
	solve_four() 
	print('Solving valid_serial_combo')
	solve_combo()
