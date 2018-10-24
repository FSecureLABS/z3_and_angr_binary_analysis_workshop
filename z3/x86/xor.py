from z3 import *

from registers import Registers
# https://c9x.me/x86/html/file_module_x86_id_330.html
def xor(state, inst):
	
	parts = inst.split(' ')
	op = parts[0]
	lhs = parts[1][:-1]
	rhs = parts[2]

	"""Performs a bitwise exclusive OR (XOR) operation on the destination (first) and source (second) operands and 
	stores the result in the destination operand location. The source operand can be an immediate, a register, or 
	a memory location; the destination operand can be a register or a memory location. (However, two memory operands 
	cannot be used in one instruction.) Each bit of the result is 1 if the corresponding bits of the operands are 
	different; each bit is 0 if the corresponding bits are the same."""
	try:
		new_val = getattr(state, lhs) ^ getattr(state, rhs)
	except:
		new_val = getattr(state, lhs) ^ int(rhs, 16)
	setattr(state, lhs, new_val)
	"""The OF and CF flags are cleared; the SF, ZF, and PF flags are set according to the result. 
	The state of the AF flag is undefined."""
	state.of = False
	state.cf = False
	zf_state = If(getattr(state, lhs) == 0, True, False)
	state.zf = zf_state
	state.eip += 1
	return state

if __name__ == "__main__":
	examples = ['xor eax, eax', 'xor ebx, 0x8', 'xor ebx, ecx']
	for example in examples:
		s = Solver()
		regs = Registers()
		regs.ebx = 4
		regs = xor(regs, example)
		s.add(regs.ebx == 12)
		print("ebx = 4, {}, ebx == 12?".format(example))
		if s.check() == sat:
			print('ebx can be 12!')
			print(s.model())
		else:
			print("ebx can't be 12")
