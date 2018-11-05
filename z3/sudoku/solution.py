from z3 import *
import sys
import random

def solve(puzzle):
	# Create a 9*9 grid
	grid = [Int(str(i)) for i in range(81)]
	s = Solver()
	# Set constraints for values we already know
	for i in range(81):
		if puzzle[i] != '.':
			s.add(grid[i] == int(puzzle[i]))
	# Set constraint that every square has a number between 0 and 9
	for i in grid:
		s.add(i >0, i <10)
	# Set constraint that every row and column only contain unique values
	for i in range(9):
		across = []
		down = []
		for j in range(9):
			down.append(grid[i+(9*j)])
			across.append(grid[(9*i)+j])
		s.add(Distinct(across))
		s.add(Distinct(down))
	# Set constraint that each sub square in the grid only contains unique values
	for q in range(3):
		for p in range(3):
			square = []
			for i in range(3):
				for j in range(3):
					index = (q*27) + (p*3) + (i * 9) + j
					square.append(grid[index])
			s.add(Distinct(square))

	for q in range(3):
		for p in range(3):
			square = []
			for i in range(3):
				for j in range(3):
					index = (q*27) + (p * 3) + (i*9) + j
					square.append(grid[index])
			s.add(Distinct(square))
	# Check if model is sat and then return a model
	if s.check() == sat:
		return s.model()
	else:
		return None

def model_to_string(model):
	"""Takes a z3 model with numbered square and turns into a long string representing a suduko board line by line"""
	tmp = {}
	for i in model:
		# z3 models are weird so everything has to be cast to python types
		tmp[int(str(i))] = str(model[i])
	return(''.join(tmp.values()))

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
	solution = solve(puzzle)
	if solution:
		out = model_to_string(solution)
		draw_puzzle(out)
	else:
		print('Unsat!')
