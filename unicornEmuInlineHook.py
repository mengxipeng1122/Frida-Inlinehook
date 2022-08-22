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


arch="x86"

patchInfos = {

    'hook' : (
0x54cc9e35 , bytes([ 233,198,97,148,235,1,216,91,45,126,210,253,125,1,216,5,126,210,253,125,86,190,66,12,111,95,41,240,139,52,36,131 ])
    ),

    'trampoline' : (
0x40610000 , bytes([ 156,80,81,82,83,85,86,87,137,225,186,53,158,204,84,232,108,0,130,40,95,94,93,91,90,89,88,157,187,66,12,111,95,233,22,158,107,20,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0 ])
    ),

    'hook_fun' : (
0x68e30080 , bytes([ 243,15,30,251,184,128,0,227,104,233,178,80,187,0,0,0,52,128,228,7,148,38,148,105,24,128,228,7,0,0,0,0 ])
    ),
}




infos =  {
"x86"    : { "archmode" : ( CS_ARCH_X86, CS_MODE_32, UC_ARCH_X86, UC_MODE_32, KS_ARCH_X86, KS_MODE_32,), 
                'retcode'   :'ret',
                'pc_reg'    : UC_X86_REG_EIP,
                'sp_reg'    : UC_X86_REG_SP,
                'pagesize'  : 4096,
                'count'     : 50,
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
    pagesize = 1024;
    if 'pagesize' in infos[arch]:
        pagesize = infos[arch]['pagesize']
    for k, (p, bs) in patchInfos.items():
        print(k,hex(p), len(bs))
        ADDRESS0= math.floor(p/pagesize)*pagesize;
        ADDRESS1= math.ceil((p+len(bs))/pagesize)*pagesize;
        SIZE    = (ADDRESS1-ADDRESS0)*0x100
        print(f"alloc memory {hex(ADDRESS0)} {hex(SIZE)}  for {k} at {hex(p)} ")
        hexdump(bs)
        try:
            mu.mem_map(ADDRESS0, SIZE);
        except unicorn.UcError as e:
            print(f'{hex(ADDRESS0)} has mapped');
            print(e)
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

