from z3 import *

from registers import Registers

from z3 import *

from registers import Registers

# https://c9x.me/x86/html/file_module_x86_id_5.html
def add(state, inst):
	
	parts = inst.split(' ')
	op = parts[0]
	lhs = parts[1][:-1]
	rhs = parts[2]

	"""Adds the first operand (destination operand) and the second operand (source operand) and stores the 
	result in the destination operand. The destination operand can be a register or a memory location; the 
	source operand can be an immediate, a register, or a memory location. (However, two memory operands cannot 
	be used in one instruction.) When an immediate value is used as an operand, it is sign-extended to 
	the length of the destination operand format.

	The ADD instruction performs integer addition. It evaluates the result for both signed and unsigned integer 
	operands and sets the OF and CF flags to indicate a carry (overflow) in the signed or unsigned result, respectively. 
	The SF flag indicates the sign of the signed result."""
	old_val = getattr(state, lhs)
	try:
		new_val = old_val + getattr(state, rhs) 
	except:
		new_val = old_val + int(rhs, 16)
	setattr(state, lhs, new_val)

	"""The OF, SF, ZF, AF, CF, and PF flags are set according to the result."""
	state.of = If(new_val < old_val, True, False)
	state.cf = If((((old_val >> 31) & 1)  ^ ((new_val >> 31) & 1)) == 1, True, False)
	zf_state = If(new_val == 0, True, False)
	state.zf = zf_state
	sf_state = If(new_val < 0, True, False)
	state.sf = sf_state
	state.eip += 1
	return state

if __name__ == "__main__":
	examples = ['add eax, 0x8', 'add esp, 0x4', 'add eax, ebx']
	for example in examples:
		s = Solver()
		regs = Registers()
		regs.eax = 0xf4
		
		regs = add(regs, example)
		
		
		s.add(regs.sf == False)
		print("eax == 0xf4, {}, sf == False?".format(example)) 		
		check = s.check()
		print(check)
		if check == sat:
			print("Model: {}".format(s.model()))
