import sys

class Rand:
	def __init__(self,seed):
		self.seed = (seed ^ 0x5DEECE66D) & ((1 << 48) - 1)

	def output_long(self,i):
		for _ in range(i):
			self.next_long()
		return self.next_long()

	def next_long(self):
		return (self.next(32) << 32) + self.next(32)

#protected synchronized int next(int bits)
#   {
#     seed = (seed * 0x5DEECE66DL + 0xBL) & ((1L << 48) - 1);
#     return (int) (seed >>> (48 - bits));
#   }

	def next(self, bits):
		self.seed = (self.seed * 0x5DEECE66D + 0xB) & ((1 << 48) - 1)
		out = (self.seed >> (48 - bits)) & 0xFFFFFFFF
		if(out & 0x80000000):
			out = -0x100000000 + out
		return out

if __name__ == "__main__":
	rand = Rand(0x1337)
	if len(sys.argv) < 2:
		print("Please provide requested output count")
		sys.exit(1)
	count = int(sys.argv[1])
	for _ in range(count):	
		print(rand.next_long())
