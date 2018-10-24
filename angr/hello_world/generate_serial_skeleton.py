import angr
import binascii

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
	pass


if __name__ == "__main__":
	base = 0x400000
	print('Solving valid_serial_one')
	solve_one(base)
	print('Solving valid_serial_two')
	solve_two(base)
