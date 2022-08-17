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


arch="arm64"

patchInfos = {

    'hook' : (
0x5e2362d914 , bytes([ 80,0,0,88,0,2,31,214,16,64,73,156,124,0,0,0,31,32,3,213,31,32,3,213,31,32,3,213,31,32,3,213 ])
    ),

    'trampoline' : (
0x7c9c494000 , bytes([ 184,160,81,156,124,0,0,0,20,217,98,35,94,0,0,0,224,7,191,169,226,15,191,169,228,23,191,169,230,31,191,169,232,39,191,169,234,47,191,169,236,55,191,169,238,63,191,169,240,71,191,169,242,79,191,169,244,87,191,169,246,95,191,169,248,103,191,169,250,111,191,169,252,119,191,169,15,66,59,213,254,63,191,169,225,3,0,145,128,253,255,88,41,253,255,88,32,1,63,214,254,63,193,168,15,66,27,213,252,119,193,168,250,111,193,168,248,103,193,168,246,95,193,168,244,87,193,168,242,79,193,168,240,71,193,168,238,63,193,168,236,55,193,168,234,47,193,168,232,39,193,168,230,31,193,168,228,23,193,168,226,15,193,168,224,7,193,168,81,0,0,88,3,0,0,20,0,216,98,131,94,0,0,0,32,2,63,214,0,72,136,82,224,1,160,114,31,32,3,213,80,0,0,88,0,2,31,214,36,217,98,35,94,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0 ])
    ),

    'hook_fun' : (
0x7c9c51a0b8 , bytes([ 144,0,0,88,241,255,255,16,0,2,31,214,0,0,0,0,64,209,217,154,124,0,0,0,112,52,29,154,124,0,0,0 ])
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

    if True:
        bs = bytes([ 0x10, 0x00, 0x00, 0xd0, 0x00, 0x02, 0x1f, 0xd6, 0xb9, 0xff, 0xff, 0x97, 0xe0, 0x03, 0x13, 0xaa])
        address=0x5ac1e3d904
        for (addr, size, mnemonic, op_str) in md.disasm_lite(bs, address):
            print("0x%x:\t%s\t%s" %(addr, mnemonic, op_str))
        

    if False:
        bs = struct.pack('IIIII', 0x97ffffbb, 0x58000051, 0x14000003, 0xD63F0220, 0xD61F0220);
        hexdump(bs)
        address = 0x62be6eb914
        for (addr, size, mnemonic, op_str) in md.disasm_lite(bs, address):
            print("0x%x:\t%s\t%s" %(addr, mnemonic, op_str))
        codes = [
            'bl	#0x62be6eb800'           ,
            'ldr	x15, #0x62be6eb920'  ,
            'b	#0x62be6eb928'           ,
            'blr	x15'                 ,
            'br	x15'                     ,
            ]
        for t,c in enumerate(codes):
            encoding, count = ks.asm(c, address+4*t);
            print(c);
            hexdump(bytes(encoding));
        raise Exception(f'exit')


        
    # patch 
    if True:
        addr=0x5e8362d800
        ADDR0 = math.floor(addr/1024)*1024
        mu.mem_map(ADDR0, 1024);
        c = infos[arch]['retcode']
        print(c)
        encoding, count = ks.asm(c);
        mu.mem_write(addr, bytes(encoding));

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

