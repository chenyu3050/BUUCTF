#! /usr/bin/env python
from pwn import *
context.log_level = 'debug'
elf=ELF('./test')
p=remote('117.21.200.166',26980)
p.send('cat flag\n')
p.recvline()
#p.interactive()
p.close()

