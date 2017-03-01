import os
from sock import Sock
s = Sock('127.0.0.1',1235)
digest = '96103df3b928d9edc5a103d690639c94628824f5'
data = 'cat.txt'
add = ':passwd'
print s.read_until('>> ')
for l in range(1,256):
    d = os.popen('hashpump -s %s -d "%s" -a %s -k %s' % (digest, data, add, l)).read()
    h = d.split('\n')[0]
    v = d.split('\n')[1]
    v = v.decode('string_escape') 
    r = h + '#' + v
    s.send(r + '\r\n')
    reply = s.read_until('>> ')
    if 'FLAG' in reply:
        print l
        print reply
        exit()
