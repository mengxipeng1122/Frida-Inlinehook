#!/usr/bin/env python
# -*- coding: utf-8 -*-

import sys
from mxp.utils import *
from xml.dom import minidom
import xml.dom.minidom as md
import xml.etree.ElementTree as ET
from capstone import *
from keystone import *
from hexdump import *

from unicorn import *
from unicorn.arm_const import *
from unicorn.arm64_const import *
from unicorn.x86_const import *


patchInfos = {

    'hook' : (
0xb3a9d6e0 , bytes([ 223,248,0,240,102,9,240,152,238,247,92,239,40,70,255,247,102,239,1,52,243,231,0,191,104,101,108,108,111,32,119,111 ])
    ),

    'trampoline' : (
0xee98f000 , bytes([ 136,128,162,238,225,214,169,179,255,180,45,233,0,95,239,243,0,128,1,180,0,191,105,70,95,248,24,0,95,248,32,64,160,71,1,188,128,243,0,136,189,232,0,95,255,188,33,70,0,191,0,191,15,242,9,14,223,248,0,240,176,213,169,179,48,70,0,191,223,248,0,240,233,214,169,179,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0 ])
    ),

    'hook_fun' : (
0xeea28088 , bytes([ 8,192,79,226,4,240,31,229,192,194,176,237,124,20,11,237,137,172,186,237,96,20,11,237,0,0,0,0,57,15,0,0 ])
    ),
}


infos =  {
"x86"    : { "archmode" : ( CS_ARCH_X86, CS_MODE_32, UC_ARCH_X86, UC_MODE_32, KS_ARCH_X86, KS_MODE_32,), 
                'retcode':'ret',
                'pc_reg': UC_X86_REG_EIP,
            },
"x64"    : { "archmode" : ( CS_ARCH_X86, CS_MODE_64, UC_ARCH_X86, UC_MODE_64, KS_ARCH_X86, KS_MODE_64,),
                'retcode':'ret',
            },
"arm64"  : { "archmode" : ( CS_ARCH_ARM64, CS_MODE_ARM, UC_ARCH_ARM64, UC_MODE_ARM, KS_ARCH_ARM64, KS_MODE_LITTLE_ENDIAN,), 
                'retcode':'bx lr',
                'sp_reg' :  UC_ARM64_REG_SP,
            },
"arm"    : { "archmode" : ( CS_ARCH_ARM, CS_MODE_ARM, UC_ARCH_ARM, UC_MODE_ARM, KS_ARCH_ARM, KS_MODE_ARM,), 
                'retcode'   :'bx lr',
                'sp_reg'    : UC_ARM_REG_SP,
                'pc_reg'    : UC_ARM_REG_PC,
            },
"thumb"  : { "archmode" : ( CS_ARCH_ARM, CS_MODE_THUMB, UC_ARCH_ARM, UC_MODE_THUMB, KS_ARCH_ARM, KS_MODE_THUMB,), 
                'retcode'   :'bx lr',
                'sp_reg'    : UC_ARM_REG_SP,
                'pc_reg'    : UC_ARM_REG_PC,
            },
}



def main():
    arch="thumb"

    cs_arch, cs_mode, uc_arch, uc_mode, ks_arch, ks_mode = infos[arch]['archmode'];
    md = Cs(cs_arch, cs_mode)
    mu = Uc(uc_arch, uc_mode)
    ks = Ks(ks_arch, ks_mode)

    # write address
    for k, (p, bs) in patchInfos.items():
        ADDRESS0= math.floor(p/1024)*1024;
        ADDRESS1= math.ceil((p+len(bs))/1024)*1024;
        SIZE    = (ADDRESS1-ADDRESS0)*0x10
        print(f"alloc memory {hex(ADDRESS1)} {hex(SIZE)}  for {k} at {hex(p)} ")
        hexdump(bs)
        try:
            mu.mem_map(ADDRESS0, SIZE);
        except unicorn.UcError:
            print(f'{hex(ADDRESS0)} has mapped');
        mu.mem_write(p, bs);

    
    # offset = 8
    # bs = patchInfos['trampoline'][1][offset:]
    # address= patchInfos['trampoline'][0] +offset
    # hexdump(bs)
    # for (addr, size, mnemonic, op_str) in md.disasm_lite(bs, address):
    #     print("0x%x:\t%s\t%s" %(addr, mnemonic, op_str))

    # path 
    if False:
        para1, hook_fun_ptr = struct.unpack('II', patchInfos['trampoline'][1][:8])
        CODE = [
    "        pushf                          ",
    "        push eax                       ",
    "        push ecx                       ",
    "        push edx                       ",
    "        push ebx                       ",
    "        push ebp                       ",
    "        push esi                       ",
    "        push edi                       ",
   f"        push {hex(para1)}              ",
    "        push esp                       ",
   f"        call {hex(hook_fun_ptr)}       ",
    "        add esp, 8                     ",
    "        pop edi                        ",
    "        pop esi                        ",
    "        pop ebp                        ",
    "        pop ebx                        ",
    "        pop edx                        ",
    "        pop ecx                        ",
    "        pop eax                        ",
    "        popf                           ",
        ]
        for c in CODE:
            print(c)
            encoding, count = ks.asm(c);
            hexdump(bytes(encoding))
    
        encoding, count = ks.asm('\n'.join(CODE));
        mu.mem_write(patchInfos['trampoline'][0]+8, bytes(encoding))
    
    code =infos[arch]['retcode'];
    encoding, count = ks.asm(code)
    mu.mem_write(patchInfos['hook_fun'][0], bytes(encoding))
    

    # allocate static  
    sp_ptr = 0x5000;
    mu.mem_map(sp_ptr-0x1000, 0x2000);
    # initialize machine registers
    mu.reg_write(infos[arch]['sp_reg'], sp_ptr)

    def hook_block(uc, address, size, user_data):
        print(">>> Tracing basic block at 0x%x, block size = 0x%x" %(address, size))
    
    # callback for tracing instructions
    def hook_code(uc, address, size, user_data):
        print(">>> Tracing instruction at 0x%x, instruction size = 0x%x" %(address, size))
        bs = uc.mem_read(address, size);
        hexdump(bs);
        for (addr, size, mnemonic, op_str) in md.disasm_lite(bs, address):
            print("0x%x:\t%s\t%s" %(addr, mnemonic, op_str))

    # callback for tracing invalid memory access (READ or WRITE)
    # def hook_mem_invalid(uc, access, address, size, value, user_data):
    #     if access == UC_MEM_WRITE_UNMAPPED:
    #         print(">>> Missing memory is being WRITE at 0x%x, data size = %u, data value = 0x%x" \
    #                 %(address, size, value))
    #         # map this memory in with 2MB in size
    #         # return True to indicate we want to continue emulation
    #         return True
    #     else:
    #         # return False to indicate we want to stop emulation
    #         return True
    # 
    
    # callback for tracing memory access (READ or WRITE)
    def hook_mem_access(uc, access, address, size, value, user_data):
        if access == UC_MEM_WRITE:
            print(">>> Memory is being WRITE at 0x%x, data size = %u, data value = 0x%x" \
                    %(address, size, value))
        else:   # READ
            print(">>> Memory is being READ at 0x%x, data size = %u" \
                    %(address, size))
    
    mu.hook_add(UC_HOOK_MEM_WRITE, hook_mem_access)
    mu.hook_add(UC_HOOK_MEM_READ, hook_mem_access)

    # tracing all basic blocks with customized callback
    #mu.hook_add(UC_HOOK_BLOCK, hook_block)

    # tracing all instructions with customized callback
    mu.hook_add(UC_HOOK_CODE, hook_code)

    # emulate machine code in infinite time
    # Note we start at ADDRESS | 1 to indicate THUMB mode.
    if arch=='thumb':
        ADDRESS = patchInfos['hook'][0] | 1;
    else:
        ADDRESS = patchInfos['hook'][0]
    try:
        mu.emu_start(ADDRESS, -1, count=26);
    except:
        print('error')
        import traceback
        traceback.print_exc()
    finally:
        print(f'pc  : {hex(mu.reg_read(infos[arch]["pc_reg"]))}');



if __name__ == '__main__':
    main()

