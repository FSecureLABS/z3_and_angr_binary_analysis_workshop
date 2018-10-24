from z3 import *

from registers import Registers

# https://c9x.me/x86/html/file_module_x86_id_147.html
def jmp(state, inst):
	parts = inst.split(' ')
	op = parts[0]
	dst = int(parts[1], 16)
	# Faking this since we don't really care for the examples we have
	state.eip == dst
	return state

if __name__ == "__main__":
	s = Solver()
	state = Registers()

	state.eip = 0x1234
	state = jmp(state, 'jmp 0x41414141')
	s.add(state.eip == 0x41414141)
	print('eip = 0x1234, jmp 0x41414141, eip == 0x41414141?')
	check = s.check()
	print(check)
	print("eip == {}".format(state.eip))
	s = Solver()
	state = Registers()
	state.eip = 0x41414141
	state = jmp(state, 'jmp 0x42424242')
	s.add(state.eip == 0x41414141)
	check = s.check()
	print('eip = 0x41414141, jmp 0x42424242, eip == 0x41414141?')
	print(check)
	if check == sat:
		print("eip == {}".format(state.eip))
