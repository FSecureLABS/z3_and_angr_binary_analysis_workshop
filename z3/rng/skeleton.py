from z3 import *
import sys

if __name__ == '__main__':
	if len(sys.argv) < 2:
		print('File of sample output required')
		sys.exit(1)
	samples_path = sys.argv[1]
	with open(samples_path, 'r') as f:
		samples = f.read().split('\n')[:-1]
	print('Loaded {} sample outputs'.format(len(samples)))
	samples = [int(x) for x in samples]

