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


arch="x64"

patchInfos = {

    'hook' : (
0x5623d77401fc , bytes([ 255,37,2,0,0,0,15,11,0,144,122,75,229,20,0,0,131,69,252,1,191,64,66,15,0,232,150,254,255,255,235,187 ])
    ),

    'trampoline' : (
0x14e54b7a9000 , bytes([ 156,65,87,65,86,65,85,65,84,65,83,65,82,65,81,65,80,80,81,82,83,85,86,87,72,137,230,72,191,252,1,116,215,35,86,0,0,232,166,16,6,0,95,94,93,91,90,89,88,65,88,65,89,65,90,65,91,65,92,65,93,65,94,65,95,157,144,144,144,144,144,144,144,144,144,144,255,37,2,0,0,0,15,11,6,2,116,215,35,86,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0 ])
    ),

    'hook_fun' : (
0x14e54b80a0d0 , bytes([ 243,15,30,250,76,141,21,245,255,255,255,255,37,7,0,0,0,15,31,128,0,0,0,0,88,18,218,73,229,20,0,0 ])
    ),
}




infos =  {
"x86"    : { "archmode" : ( CS_ARCH_X86, CS_MODE_32, UC_ARCH_X86, UC_MODE_32, KS_ARCH_X86, KS_MODE_32,), 
                'retcode'   :'ret',
                'pc_reg'    : UC_X86_REG_EIP,
                'sp_reg'    : UC_X86_REG_SP,
            },
"x64"    : { "archmode" : ( CS_ARCH_X86, CS_MODE_64, UC_ARCH_X86, UC_MODE_64, KS_ARCH_X86, KS_MODE_64,),
                'retcode'   :'ret',
                'sp_reg'    : UC_X86_REG_ESP,
                'pc_reg'    : UC_X86_REG_EIP,
                'count': 60,
            },
"arm64"  : { "archmode" : ( CS_ARCH_ARM64, CS_MODE_ARM, UC_ARCH_ARM64, UC_MODE_ARM, KS_ARCH_ARM64, KS_MODE_LITTLE_ENDIAN,), 
                'retcode':'RET',
                'pc_reg': UC_ARM64_REG_PC,
                'sp_reg' :  UC_ARM64_REG_SP,
                'count':52,
                'inspect_regs':{
                    'x11': UC_ARM64_REG_X11,
                    'x17': UC_ARM64_REG_X17,
                },
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


    if False:
        addr=0x5ac1e3d904
        CODE = [
    f"        adrp	x16, #{hex(addr+0x08)}              ",
    f"        br   x16              ",
        ]
        for c in CODE:
            print(c)
            encoding, count = ks.asm(c);
            hexdump(bytes(encoding))
    
        encoding, count = ks.asm('\n'.join(CODE));
        mu.mem_write(addr, bytes(encoding))
    
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
        count=26;
        if 'count' in infos[arch]:
            count=infos[arch]['count']
        mu.emu_start(ADDRESS, -1, count=count);
    except:
        print('error')
        import traceback
        traceback.print_exc()
    finally:
        print(f'pc  : {hex(mu.reg_read(infos[arch]["pc_reg"]))}');
        if 'inspect_regs' in infos[arch]:
            for k, v in infos[arch]['inspect_regs'].items():
                print(f'{k}  : {hex(mu.reg_read(v))}');



if __name__ == '__main__':
    main()

