from z3 import *

from registers import Registers


# http://unixwiz.net/techtips/x86-jumps.html
def jg(state, inst):
	parts = inst.split(' ')
	op = parts[0]
	dst = int(parts[1], 16)
	
	"""
	mnemonic Description				signed 	conditions
	JG   	 Jump if greater 
	JNLE 	 Jump if not less or equal	signed	ZF = 0 and SF = OF
	"""

	return state

if __name__ == "__main__":
	s = Solver()
	state = Registers()

	state.zf = False
	state.sf = True
	state.of = True
	state.eip = 0x1234
	print('zf = False, sf = True, of = True, eip = 0x1234 => jg 0x41414141 => state.eip == 0x41414141?')
	state = jg(state, 'jg 0x41414141')
	s.add(state.eip == 0x41414141)
	check = s.check()
	print(check)

	s = Solver()
	state = Registers()
	state.zf = False
	state.sf = True
	state.of = False
	state.eip = 0x41414140
	print('zf = False, sf = True, of = True, eip = 0x41414140 => jg 0x42424242 => state.eip == 0x41414141?')
	state = jg(state, 'jg 0x42424242')
	s.add(state.eip == 0x41414141)
	check = s.check()
	print(check)