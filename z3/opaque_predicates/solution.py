from z3 import *

class Registers:

	def __init__(self):
		self.eax = BitVec('eax', 32)
		self.ebx = BitVec('ebx', 32)
		self.ecx = BitVec('ecx', 32)
		self.edx = BitVec('edx', 32)
		self.edi = BitVec('edi', 32)
		self.esi = BitVec('esi', 32)
		self.ebp = BitVec('ebp', 32)
		self.esp = BitVec('esp', 32)

		self.eip = BitVec('eip', 32)

		self.cf = Bool('cf')
		self.zf = Bool('zf')
		self.sf = Bool('sf')
		self.of = Bool('of')

def add(state, inst):
	
	parts = inst.split(' ')
	op = parts[0]
	lhs = parts[1][:-1]
	rhs = parts[2]

	old_val = getattr(state, lhs)
	try:
		new_val = old_val + getattr(state, rhs) 
	except:
		new_val = old_val + int(rhs, 16)
	setattr(state, lhs, new_val)

	state.of = If(new_val < old_val, True, False)
	state.cf = If((((old_val >> 31) & 1)  ^ ((new_val >> 31) & 1)) == 1, True, False)
	zf_state = If(new_val == 0, True, False)
	state.zf = zf_state
	sf_state = If(new_val < 0, True, False)
	state.sf = sf_state
	state.eip += 1
	return state

def xor(state, inst):
	
	parts = inst.split(' ')
	op = parts[0]
	lhs = parts[1][:-1]
	rhs = parts[2]

	old_val = getattr(state, lhs)
	try:
		new_val = old_val ^ getattr(state, rhs) 
	except:
		new_val = old_val ^ int(rhs, 16)

	setattr(state, lhs, new_val)
	state.of = False
	state.cf = False
	zf_state = If(new_val == 0, True, False)
	state.zf = zf_state
	state.sf = If(new_val < 0, True, False)
	state.eip += 1
	return state

def jnz(state, inst):
	parts = inst.split(' ')
	op = parts[0]
	dst = int(parts[1], 16)
	new_eip = If(state.zf == False, dst, state.eip + 1)
	state.eip = new_eip
	return state


def or_inst(state, inst):
	parts = inst.split(' ')
	op = parts[0]
	lhs = parts[1][:-1]
	rhs = parts[2]

	try:
		new_val = getattr(state, lhs) | getattr(state, rhs)
	except:
		new_val = getattr(state, lhs) | int(rhs, 16)
	setattr(state, lhs, new_val)
	state.of = False
	state.cf = False
	state.sf = If(new_val < 0, True, False)
	zf_state = If(new_val == 0, True, False)
	state.zf = zf_state
	state.eip += 1
	return state

def sub(state, inst):
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

	state.of = If((((old_val >> 31) & 1)  ^ ((new_val >> 31) & 1)) == 1, True, False)
	state.cf = If(old_val < rhs_val, True, False)
	zf_state = If(new_val == 0, True, False)
	state.zf = zf_state
	sf_state = If(new_val < 0, True, False)
	state.sf = sf_state
	state.eip += 1
	return state

def jg(state, inst):
	parts = inst.split(' ')
	op = parts[0]
	dst = int(parts[1], 16)
	new_eip = If(And(state.zf == False, state.sf == state.of), dst, state.eip + 1)
	state.eip = new_eip
	return state

def run_prog(instrutions):
	state = Registers()
	state.eip = 0
	s_one = Solver()
	s_two = Solver()
	for inst in instrutions:
		parts = inst.split(' ')
		op = parts[0]
		if op == 'add':
			state = add(state, inst)
		elif op == 'sub':
			state = sub(state, inst)
		elif op == 'or':
			state = or_inst(state, inst)
		elif op == 'xor':
			state = xor(state, inst)
		elif op == 'jg':
			state = jg(state, inst)
			dst = int(parts[1], 16)
			s_one.add(state.eip == dst)
			s_two.add(state.eip != dst)
		elif op == 'jnz':
			state = jnz(state, inst)
			dst = int(parts[1], 16)
			s_one.add(state.eip == dst)
			s_two.add(state.eip != dst)
	if s_two.check() == sat and s_one.check() == sat:
		print('Not an opaque predicate!')
	else:
		print('Opaque predicate!')


if __name__ == "__main__":
	tests = [
		['xor eax, eax', 'jnz 0x41414141'],
		['xor eax, ebx', 'jnz 0x42424242'],
		['add eax, eax', 'jnz 0x43434343'],
		['sub eax, 0x7', 'jg 0x41414141'],
		['xor eax, eax', 'sub eax, 0x16', 'jg 0x13371337']
	]

	for test in tests:
		print("Running test: {}".format(test))
		run_prog(test)
