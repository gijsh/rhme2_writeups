labels = {}

def add(r1,r2):
    return '08' + format(r1,'x') + format(r2,'x')

def sub(r1,r2):
    return '09' + format(r1,'x') + format(r2,'x')

def xor(r1,r2):
    return '0a' + format(r1,'x') + format(r2,'x')

def movh(r,v):
    assert(v <= 0xffff)
    return '05' + format(r,'x') + '0%.4x' % v

def movl(r,v):
    assert(v <= 0xffff)
    return '04' + format(r,'x') + '0%.4x' % v

def cmp(r1,r2):
    return '16' + format(r1,'x') + format(r2,'x')

def ret():
    return '13'

def nop():
    return '00'

def rol(r1,r2):
    return '10' + format(r1,'x') + format(r2,'x')

def ror(r1,r2):
    return '11' + format(r1,'x') + format(r2,'x')

def lodsb(r1,r2):
    return '06' + format(r1,'x') + format(r2,'x')

def stosb(r1,r2):
    return '07' + format(r1,'x') + format(r2,'x')

def push(r):
    return '01' + format(r,'x') + '0'

def pop(r):
    return '02' + format(r,'x') + '0'

def logic_not(r):
    return '0d' + format(r,'x') + '0'

def call(r):
    return '12' + format(r,'x') + '0'

def jnz(a):
    a = labels[a]
    assert(a % 4 == 0)
    return '18' + '%.4x' % (a/4)

def jmp(a):
    a = labels[a]
    assert(a % 4 == 0)
    return '14' + '%.4x' % (a/4)

def rjmp(r):
    return '15' + format(r,'x') + '0'

def read(r):
    return '1b' + format(r,'x') + '0'

def write(r):
    return '1c' + format(r,'x') + '0'

def mov(r1,r2):
    return '03' + format(r1,'x') + format(r2,'x')

def do_exit():
    return '1f'

def label(n, r):
    o = ''
    while (len(r) + len(o)) % 8:
        o += '00'
    labels[n] = (len(r) + len(o)) / 2
    return o


(r0, r1, r2, r3, r4, r5, sp, ip, r8, r9) = list(range(10))
