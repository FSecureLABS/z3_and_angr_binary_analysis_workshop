from z3 import *
import sys
from itertools import cycle

#from http://stackoverflow.com/a/22549054
def abs(x):
	return If(x >= 0,x,-x)

def generate_chessboard(n):
	# Generates alternating color chessboard as nested lists of rows
	colors = cycle(["\033[0;40m  \033[00m","\033[0;47m  \033[00m"])
	chessboard = []
	for i in range(n):
		chessboard.append([next(colors) for _ in range(n)])
		if not n % 2: next(colors)
	chessboard = cycle(chessboard)
	chessboard = [next(chessboard) for _ in range(n)]
	chessboard = list(reversed(chessboard))
	return chessboard

if __name__ == "__main__":
	if len(sys.argv) < 2:
		print("usage: python solution.py $grid_size")
		print('example: python solution.py 4')
		sys.exit(0)
	n = int(sys.argv[1])
	print('Solving N Queens for a {} by {} chess board'.format(n, n))
	# Instantiate solver
	s = Solver()
	# Creating row and column co-ordinates for each queen
	columns = [Int('col_%d' % i) for i in range(n)]
	rows = [Int('row_%d' % i) for i in range(n)]
	# Should only be one queen per row or column
	s.add(Distinct(rows))
	s.add(Distinct(columns))

	# Each cell should have a value within the boards co-ordinates
	for i in range(n):
		s.add(columns[i] >= 0,columns[i] < n, rows[i] >= 0, rows[i] < n)
	# No queens should be to take each other
	for i in range(n - 1):
		for j in range(i + 1, n):
			s.add(abs(columns[i] - columns[j]) != abs(rows[i] - rows[j]))

	if s.check() != sat:
		print('unsat :(')
		sys.exit(1)

	m = s.model()
	chessboard = generate_chessboard(n)
	# Match up column and rows into co-ordinate pairs
	for x, y in zip(columns, rows):
		# Extract co-ordinates and places queens at each location
		chessboard[m[x].as_long()][m[y].as_long()] = 'Q '

	# Flatten nested lists into a string to display
	for i in chessboard:
		out = ""
		for j in i:
			out += j
		# Print each sub list as a row
		print(out)
