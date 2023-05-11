
'use strict';

import { readArrayBufferFromMemory } from "./commutils";
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
        let distance = to.sub(from.add(5));
        const G_MININT32 =( -2147483648); 
        const G_MAXINT32 =(  2147483647);
        if (distance.compare(G_MININT32)>=0 && distance.compare(G_MAXINT32)<0) return 5;
        else return 0x10;
    }

    relocCode(from: NativePointer, to: NativePointer, sz: number): [number, ArrayBuffer] {
        //TODO: warning,  X86relocator does handle long call correctly.
        let woffset = 0;
        const writer = new X86Writer(to);
        const relocator = new X86Relocator(from,writer);
        const max_cnt=20;
        let cnt = 0;
        let offset;
        while((offset= relocator.readOne())<=sz){
            if(cnt>=max_cnt) break;
            if(relocator.input==null) throw new Error('input in relocator is null')
            relocator.writeOne();
            cnt ++ ;
        }
        woffset = writer.offset;
        let orig_bytes = readArrayBufferFromMemory(from, offset);
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
