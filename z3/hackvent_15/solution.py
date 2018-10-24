#We've captured a strange message. It looks like it is encrypted somehow ...
#iw, hu, fv, lu, dv, cy, og, lc, gy, fq, od, lo, fq, is, ig, gu, hs, hi, ds, cy, oo, os, iu, fs, gu, lh, dq, lv, gu, iw, hv, gu, di, hs, cy, oc, iw, gc


#We've also intercepted what seems to be a hint to the key:
#bytwycju + yzvyjjdy ^ vugljtyn + ugdztnwv | xbfziozy = bzuwtwol
#    ^         ^          ^          ^          ^
#wwnnnqbw - uclfqvdu & oncycbxh | oqcnwbsd ^ cgyoyfjg = vyhyjivb
#    &         &          &          &          &
#yzdgotby | oigsjgoj | ttligxut - dhcqxtfw & szblgodf = sfgsoxdd
#    +         +          +          +          +
#yjjowdqh & niiqztgs + ctvtwysu & diffhlnl - thhwohwn = xsvuojtx
#    -         -           -         -          -
#nttuhlnq ^ oqbctlzh - nshtztns ^ htwizvwi + udluvhcz = syhjizjq
#    =         =           =         =          =         
#fjivucti   zoljwdfl   sugvqgww   uxztiywn   jqxizzxq

from z3 import *  
import sys

encrypted = "iw, hu, fv, lu, dv, cy, og, lc, gy, fq, od, lo, fq, is, ig, gu, hs, hi, ds, cy, oo, os, iu, fs, gu, lh, dq, lv, gu, iw, hv, gu, di, hs, cy, oc, iw, gc"

if __name__ == "__main__": 
	b = BitVec('b', 32)
	c = BitVec('c', 32)
	d = BitVec('d', 32)
	f = BitVec('f', 32)
	g = BitVec('g', 32)
	h = BitVec('h', 32)
	i = BitVec('i', 32)
	j = BitVec('j', 32)
	l = BitVec('l', 32)
	n = BitVec('n', 32)
	o = BitVec('o', 32)
	q = BitVec('q', 32)
	s = BitVec('s', 32)
	t = BitVec('t', 32)
	u = BitVec('u', 32)
	v = BitVec('v', 32)
	w = BitVec('w', 32)
	x = BitVec('x', 32)
	y = BitVec('y', 32)
	z = BitVec('z', 32)
	solv = Solver()
	solv.append(b < 10, b >= 0)
	solv.append(c < 10, c >= 0)
	solv.append(d < 10, d >= 0)
	solv.append(f < 10, f >= 0)
	solv.append(g < 10, g >= 0)
	solv.append(h < 10, h >= 0)
	solv.append(i < 10, i >= 0)
	solv.append(j < 10, j >= 0)
	solv.append(l < 10, l >= 0)
	solv.append(n < 10, n >= 0)
	solv.append(o < 10, o >= 0)
	solv.append(q < 10, q > 0)
	solv.append(s < 10, s >= 0)
	solv.append(t < 10, t >= 0)
	solv.append(u < 10, u >= 0)
	solv.append(v < 10, v >= 0)
	solv.append(w < 10, w >= 0)
	solv.append(x < 10, x >= 0)
	solv.append(y < 10, y >= 0)
	solv.append(z < 10, z >= 0)
	bytwycju=u*1+j*10+c*100+y*1000+w*10000+t*100000+y*1000000+b*10000000
	yzvyjjdy=y*1+d*10+j*100+j*1000+y*10000+v*100000+z*1000000+y*10000000
	vugljtyn=n*1+y*10+t*100+j*1000+l*10000+g*100000+u*1000000+v*10000000
	ugdztnwv=v*1+w*10+n*100+t*1000+z*10000+d*100000+g*1000000+u*10000000
	xbfziozy=y*1+z*10+o*100+i*1000+z*10000+f*100000+b*1000000+x*10000000
	bzuwtwol=l*1+o*10+w*100+t*1000+w*10000+u*100000+z*1000000+b*10000000
	wwnnnqbw=w*1+b*10+q*100+n*1000+n*10000+n*100000+w*1000000+w*10000000
	uclfqvdu=u*1+d*10+v*100+q*1000+f*10000+l*100000+c*1000000+u*10000000
	oncycbxh=h*1+x*10+b*100+c*1000+y*10000+c*100000+n*1000000+o*10000000
	oqcnwbsd=d*1+s*10+b*100+w*1000+n*10000+c*100000+q*1000000+o*10000000
	cgyoyfjg=g*1+j*10+f*100+y*1000+o*10000+y*100000+g*1000000+c*10000000
	vyhyjivb=b*1+v*10+i*100+j*1000+y*10000+h*100000+y*1000000+v*10000000
	yzdgotby=y*1+b*10+t*100+o*1000+g*10000+d*100000+z*1000000+y*10000000
	oigsjgoj=j*1+o*10+g*100+j*1000+s*10000+g*100000+i*1000000+o*10000000
	ttligxut=t*1+u*10+x*100+g*1000+i*10000+l*100000+t*1000000+t*10000000
	dhcqxtfw=w*1+f*10+t*100+x*1000+q*10000+c*100000+h*1000000+d*10000000
	szblgodf=f*1+d*10+o*100+g*1000+l*10000+b*100000+z*1000000+s*10000000
	sfgsoxdd=d*1+d*10+x*100+o*1000+s*10000+g*100000+f*1000000+s*10000000
	yjjowdqh=h*1+q*10+d*100+w*1000+o*10000+j*100000+j*1000000+y*10000000
	niiqztgs=s*1+g*10+t*100+z*1000+q*10000+i*100000+i*1000000+n*10000000
	ctvtwysu=u*1+s*10+y*100+w*1000+t*10000+v*100000+t*1000000+c*10000000
	diffhlnl=l*1+n*10+l*100+h*1000+f*10000+f*100000+i*1000000+d*10000000
	thhwohwn=n*1+w*10+h*100+o*1000+w*10000+h*100000+h*1000000+t*10000000
	xsvuojtx=x*1+t*10+j*100+o*1000+u*10000+v*100000+s*1000000+x*10000000
	nttuhlnq=q*1+n*10+l*100+h*1000+u*10000+t*100000+t*1000000+n*10000000
	oqbctlzh=h*1+z*10+l*100+t*1000+c*10000+b*100000+q*1000000+o*10000000
	nshtztns=s*1+n*10+t*100+z*1000+t*10000+h*100000+s*1000000+n*10000000
	htwizvwi=i*1+w*10+v*100+z*1000+i*10000+w*100000+t*1000000+h*10000000
	udluvhcz=z*1+c*10+h*100+v*1000+u*10000+l*100000+d*1000000+u*10000000
	syhjizjq=q*1+j*10+z*100+i*1000+j*10000+h*100000+y*1000000+s*10000000
	fjivucti=i*1+t*10+c*100+u*1000+v*10000+i*100000+j*1000000+f*10000000
	zoljwdfl=l*1+f*10+d*100+w*1000+j*10000+l*100000+o*1000000+z*10000000
	sugvqgww=w*1+w*10+g*100+q*1000+v*10000+g*100000+u*1000000+s*10000000
	uxztiywn=n*1+w*10+y*100+i*1000+t*10000+z*100000+x*1000000+u*10000000
	jqxizzxq=q*1+x*10+z*100+z*1000+i*10000+x*100000+q*1000000+j*10000000
	solv.add(bytwycju + yzvyjjdy ^ vugljtyn + ugdztnwv | xbfziozy == bzuwtwol)
	solv.add(wwnnnqbw - uclfqvdu & oncycbxh | oqcnwbsd ^ cgyoyfjg == vyhyjivb)
	solv.add(yzdgotby | oigsjgoj | ttligxut - dhcqxtfw & szblgodf == sfgsoxdd)
	solv.add(yjjowdqh & niiqztgs + ctvtwysu & diffhlnl - thhwohwn == xsvuojtx)
	solv.add(nttuhlnq ^ oqbctlzh - nshtztns ^ htwizvwi + udluvhcz == syhjizjq)
	solv.add(bytwycju ^ wwnnnqbw & yzdgotby + yjjowdqh - nttuhlnq == fjivucti)
	solv.add(yzvyjjdy ^ uclfqvdu & oigsjgoj + niiqztgs - oqbctlzh == zoljwdfl)
	solv.add(vugljtyn ^ oncycbxh & ttligxut + ctvtwysu - nshtztns == sugvqgww)
	solv.add(ugdztnwv ^ oqcnwbsd & dhcqxtfw + diffhlnl - htwizvwi == uxztiywn)
	solv.add(xbfziozy ^ cgyoyfjg & 	szblgodf + thhwohwn - udluvhcz == jqxizzxq)
	model_map = {}
	ascii = ""
	if solv.check():
		# Code cracked
		model = solv.model()
		# Create a code book
		for i in model:
			model_map[str(i)] = str(model[i])
		# Translate the coded message
		for p in encrypted.split(', '):
			tmp = ""
			for c in p:
				tmp += model_map[c]
			ascii += chr(int(tmp))
		print(ascii)
	else:
		print("unsat :(")
