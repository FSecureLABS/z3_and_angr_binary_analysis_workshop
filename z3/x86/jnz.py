from z3 import *

from registers import Registers

# http://unixwiz.net/techtips/x86-jumps.html
def jnz(state, inst):
	parts = inst.split(' ')
	op = parts[0]
	dst = int(parts[1], 16)

	"""
	mnemonic Description				signed 	conditions
	JNE 	 Jump if not equal 			N/A		ZF = 0
	JNZ		 Jump if not zero			N/A		ZF = 0
	"""


	new_eip = If(state.zf == False, dst, state.eip + 1)
	state.eip = new_eip
	return state

if __name__ == "__main__":
	s = Solver()
	state = Registers()

	state.zf = False
	state.eip = 0x1234
	state = jnz(state, 'jnz 0x41414141')
	s.add(state.eip == 0x41414141)
	check = s.check()
	print('zf = False, eip = 0x1234, jnz 0x41414141, eip == 0x41414141?')
	print(check)
	s = Solver()
	state = Registers()
	state.zf = True
	state.eip = 0x41414141
	state = jnz(state, 'jnz 0x42424242')
	s.add(state.eip == 0x41414141)
	check = s.check()
	print('zf = True, eip = 0x41414141, jnz 0x42424242, eip == 0x41414141?')
	print(check)
