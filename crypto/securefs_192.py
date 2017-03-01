import hashlib
from Crypto.Util.number import inverse
# Find using binary search
q = 0xFFFFFFFFFFFFFFFFFFFFFFFF99DEF836146BC9B1B4D22831
r = 0x897703036b2e18116b36353d92ac3dd978845fc99a735b8a 

h1 = int(hashlib.sha1('cat.txt').hexdigest(),16)
s1 = 0xdfd0f4a25b7d529e89ac030c2b681e93831e95a8186823b9
h2 = int(hashlib.sha1('cat.txt:finances.csv').hexdigest(),16)
s2 = 0xf2bca35d472116dc6d5bebe96f1a3af249be78c63219a0dc

a = (s1-s2)
b = (h1-h2)
k_inv = (a * inverse(b,q)) % q
kxr = (s1-k_inv*h1) % q

want =  int(hashlib.sha1('passwd').hexdigest()[:48],16)
s = (k_inv*want + kxr) % q
print '%.48x%.48x#passwd' % (r,s)
