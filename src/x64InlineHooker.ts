
'use strict';

import { readMemoryArrayBuffer } from "../commutils";
import { InlineHooker } from "./InlineHooker";

export class X64InlineHooker extends InlineHooker{
    putPrecode(p:NativePointer):[number, NativePointer] {
        const writer = new X86Writer(p);
        writer.putPushfx();
        writer.putPushReg('r15');
        writer.putPushReg('r14');
        writer.putPushReg('r13');
        writer.putPushReg('r12');
        writer.putPushReg('r11');
        writer.putPushReg('r10');
        writer.putPushReg('r9');
        writer.putPushReg('r8');
        writer.putPushReg('rax');
        writer.putPushReg('rcx');
        writer.putPushReg('rdx');
        writer.putPushReg('rbx');
        writer.putPushReg('rbp');
        writer.putPushReg('rsi');
        writer.putPushReg('rdi');
        writer.putMovRegReg('rsi','rsp');
        writer.putMovRegAddress('rdi', this.para1);
        writer.putCallAddress(this.hook_fun_ptr)
        writer.putPopReg('rdi');
        writer.putPopReg('rsi');
        writer.putPopReg('rbp');
        writer.putPopReg('rbx');
        writer.putPopReg('rdx');
        writer.putPopReg('rcx');
        writer.putPopReg('rax');
        writer.putPopReg('r8');
        writer.putPopReg('r9');
        writer.putPopReg('r10');
        writer.putPopReg('r11');
        writer.putPopReg('r12');
        writer.putPopReg('r13');
        writer.putPopReg('r14');
        writer.putPopReg('r15');
        writer.putPopfx();
        writer.flush()
        return [ writer.offset, p];
    }

    getJumpInstLen(from: NativePointer, to: NativePointer): number {
        return 5; // alway jmp 
    }

    relocCode(from: NativePointer, to: NativePointer, sz: number): [number, ArrayBuffer] {
        let offset = 0;
        let woffset = 0;
        const writer = new X86Writer(to);
        const relocator = new X86Relocator(from,writer);
        const max_cnt=10;
        let cnt = 0;
        while(cnt<max_cnt && offset<sz){
            let inst = relocator.readOne();
            console.log(JSON.stringify(inst))
            if(relocator.input==null) throw new Error('input in relocator is null')
            offset += relocator.input.size;
            relocator.writeOne();
            cnt ++ ;
        }
        woffset = writer.offset;
        console.log(`thumb reloc write length ${woffset}`)
        let orig_bytes = readMemoryArrayBuffer(from, offset);
        return [woffset, orig_bytes]
    }

    putJumpCode(from: NativePointer, to: NativePointer): number {
        const writer = new X86Writer(from);
        writer.putJmpAddress(to);
        writer.flush();
        return writer.offset;
    }

}

export let getRegs = (sp:NativePointer) =>{
    return  {
flag: sp.add(Process.pointerSize*15).readPointer(),
r15 : sp.add(Process.pointerSize*14).readPointer(),
r14 : sp.add(Process.pointerSize*13).readPointer(),
r13 : sp.add(Process.pointerSize*12).readPointer(),
r12 : sp.add(Process.pointerSize*11).readPointer(),
r11 : sp.add(Process.pointerSize*10).readPointer(),
r10 : sp.add(Process.pointerSize*9 ).readPointer(),
r9  : sp.add(Process.pointerSize*8 ).readPointer(),
r8  : sp.add(Process.pointerSize*7 ).readPointer(),
eax : sp.add(Process.pointerSize*6 ).readPointer(),
ecx : sp.add(Process.pointerSize*5 ).readPointer(),
edx : sp.add(Process.pointerSize*4 ).readPointer(),
ebx : sp.add(Process.pointerSize*3 ).readPointer(),
ebp : sp.add(Process.pointerSize*2 ).readPointer(),
esi : sp.add(Process.pointerSize*1 ).readPointer(),
edi : sp.add(Process.pointerSize*0 ).readPointer(),
    };
}
