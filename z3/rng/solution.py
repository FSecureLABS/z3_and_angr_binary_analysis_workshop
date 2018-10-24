from z3 import *
import sys

def next_long():
	start = next(32)
	end = next(32)
	out = (start << 32) + end
	return out

def next(bits):
	global seed
	seed = (seed * 0x5DEECE66D + 0xB) & ((1 << 48) - 1)
	out = LShR(seed, (48 - bits)) & 0xFFFFFFFF
	out = If(out & 0x80000000 != 0, -0x100000000 + out, out)
	return out

if __name__ == '__main__':
	if len(sys.argv) < 2:
		print('File of sample output required')
		sys.exit(1)
	samples_path = sys.argv[1]
	with open(samples_path, 'r') as f:
		samples = f.read().split('\n')[:-1]
	print('Loaded {} sample outputs'.format(len(samples)))
	samples = [int(x) for x in samples]
	global seed
	seed = BitVec('seed', 64)
	seed = (seed ^ 0x5DEECE66D) & ((1 << 48) - 1)
	s=Solver()
	for i in range(len(samples)):
		s.add(next_long() == samples[i])
	tmp = s.check()
	print(s.model())
