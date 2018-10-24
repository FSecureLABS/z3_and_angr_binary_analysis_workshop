from z3 import *
import sys
import random

def solve(puzzle):
	# Puzzle is an 81 character string representing a suduko board
	# '.' characters are used for unknown squares and numbers for known
	# values, return a string representing a completed suduko board	
	pass

# Print a rather vague Suduko board
def draw_puzzle(puzzle):
	for i in range(9):
		out = "|"
		for j in range(9):
			out += str(puzzle[(9*i)+j]) + "|"
		print(out)

if __name__ == "__main__":
	if len(sys.argv) < 2:
		print("path to testcase file expected")
		sys.exit(1)
	test_path = sys.argv[1]
	with open(test_path, 'r') as f:
		samples = f.read().split('\n')[:-1]
	print("Selecting random puzzle out of {} samples".format(len(samples)))
	puzzle = random.choice(samples)
	draw_puzzle(puzzle)
	print("")
	print("-" * 30)
	print("")
	# Solve the puzzle?
	solution = solve(puzzle)
	# Draw solved grid
	#draw_puzzle(solution)