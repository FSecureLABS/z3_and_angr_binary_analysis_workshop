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
