from z3 import Solver,BitVec
i = [BitVec('i_%i' % i,8) for i in range(13)]
s = Solver()
s.add(i[7] + i[8] == 0xd3)
s.add(i[8] * i[9] == 0x15c0)
s.add(i[0] * i[1] == 0x13b7)
s.add(i[2] * i[3] == 0x1782)
s.add(i[3] + i[4] == 0x92)
s.add(i[6] * i[7] == 0x2b0c)
s.add(i[5] + i[6] == 0xa5)
s.add(i[9] + i[10] == 0x8f)
s.add(i[1] + i[2] == 0xa7)
s.add(i[10] * i[11] == 0x2873)
s.add(i[12] * 13 == 0x297)
s.add(i[4] * i[5] == 0x122f)
s.add(i[11] + i[12] == 0xa0)
for x in range(13):
    s.add(i[x] >= 0)

s.check()
m = s.model()
o = [chr(int(m[x].as_long())) for x in i]
print ''.join(o)
