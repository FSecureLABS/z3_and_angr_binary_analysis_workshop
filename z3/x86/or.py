from z3 import *

from registers import Registers

# https://c9x.me/x86/html/file_module_x86_id_219.html
def or_inst(state, inst):
	parts = inst.split(' ')
	op = parts[0]
	lhs = parts[1][:-1]
	rhs = parts[2]
	"""Performs a bitwise inclusive OR operation between the destination (first) and source (second) 
	operands and stores the result in the destination operand location. The source operand can be an 
	immediate, a register, or a memory location; the destination operand can be a register or a memory 
	location. (However, two memory operands cannot be used in one instruction.) Each bit of the result 
	of the OR instruction is set to 0 if both corresponding bits of the first and second operands are 0; 
	otherwise, each bit is set to 1. """


	"""The OF and CF flags are cleared; the SF, ZF, and PF flags are set according to the result. The state of the AF flag is undefined."""
	return state

if __name__ == "__main__":
	test_cases = ['or eax, 0x8', 'or ebx, ecx', 'or eax, ebx']
	for test in test_cases:
		s = Solver()
		state = Registers()
		state.eax = 0x7
		state = or_inst(state, test)
		s.add(state.eax == 0x7)
		print("eax = 0x7, {}, eax == 0x7?".format(test))
		if s.check() == sat:
			print('Eax can be 0x7!')
			print(s.model())
		else:
			print("Eax can't be 0x7 :(")
