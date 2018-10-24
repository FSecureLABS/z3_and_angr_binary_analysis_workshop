from z3 import *

from registers import Registers

# https://c9x.me/x86/html/file_module_x86_id_308.html
def sub(state, inst):
	"""
	Subtracts the second operand (source operand) from the first operand (destination operand)
	and stores the result in the destination operand. The destination operand can be a register
	or a memory location; the source operand can be an immediate, register, or memory location.

	The SUB instruction performs integer subtraction. It evaluates the result for both signed
	and unsigned integer operands and sets the OF and CF flags to indicate an overflow in the 
	signed or unsigned result, respectively. The SF flag indicates the sign of the signed result
	"""

	parts = inst.split(' ')
	op = parts[0]
	lhs = parts[1][:-1]
	rhs = parts[2]

	old_val = getattr(state, lhs)

	try:
		rhs_val = getattr(state, rhs) 
	except:
		rhs_val = int(rhs, 16)
	new_val = old_val - rhs_val
	setattr(state, lhs, new_val)

	"The OF, SF, ZF, AF, PF, and CF flags are set according to the result."
	state.of = If((((old_val >> 31) & 1)  ^ ((new_val >> 31) & 1)) == 1, True, False)
	state.cf = If(old_val < rhs_val, True, False)
	zf_state = If(new_val == 0, True, False)
	state.zf = zf_state
	sf_state = If(new_val < 0, True, False)
	state.sf = sf_state
	state.eip += 1
	return state

if __name__ == "__main__":
	test_cases = ['sub eax, 0x8', 'sub eax, ecx', 'sub eax, eax']
	for test in test_cases:
		s = Solver()
		state = Registers()
		state.eax = 0x7
		state = sub(state, test)
		s.add(state.eax == 0)
		print("eax = 0x7, {}, eax == 0?".format(test))
		if s.check() == sat:
			print('Eax can be 0x0!')
			print(s.model())
		else:
			print("Eax can't be 0x0 :(")
