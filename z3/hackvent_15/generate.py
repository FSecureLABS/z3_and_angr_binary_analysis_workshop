var = ['bytwycju','yzvyjjdy','vugljtyn','ugdztnwv','xbfziozy','bzuwtwol',
'wwnnnqbw','uclfqvdu','oncycbxh','oqcnwbsd','cgyoyfjg','vyhyjivb',
'yzdgotby','oigsjgoj','ttligxut','dhcqxtfw','szblgodf','sfgsoxdd',
'yjjowdqh','niiqztgs','ctvtwysu','diffhlnl','thhwohwn','xsvuojtx',
'nttuhlnq','oqbctlzh','nshtztns','htwizvwi','udluvhcz','syhjizjq','fjivucti','zoljwdfl','sugvqgww','uxztiywn','jqxizzxq']

s = set()
for i in var:
	for c in i:
		s.add(c)
for c in s:
	print("{} = BitVec('{}',32)".format(c, c))
print("solv = Solver()")
for c in s:
	print("solv.append({} < 10, {} >= 0)".format(c, c))
for i in var:
	out = ""
	out += i + "="
	i = list(reversed(i))
	for c in range(0,len(i)):
		out+= "{}*1{}+".format(i[c], "0"*c)
	print(out[:-1])
