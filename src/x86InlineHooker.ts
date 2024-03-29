
'use strict';

import { readArrayBufferFromMemory } from "./commutils";
import { InlineHooker } from "./InlineHooker";

export class X86InlineHooker extends InlineHooker{
    putPrecode(p:NativePointer):[number, NativePointer] {
        const writer = new X86Writer(p);
        writer.putPushfx();
        writer.putPushReg('eax');
        writer.putPushReg('ecx');
        writer.putPushReg('edx');
        writer.putPushReg('ebx');
        writer.putPushReg('ebp');
        writer.putPushReg('esi');
        writer.putPushReg('edi');
        writer.putMovRegReg('ecx','esp');
        writer.putMovRegAddress('edx', this.para1);
        writer.putCallAddress(this.hook_fun_ptr)
        writer.putPopReg('edi');
        writer.putPopReg('esi');
        writer.putPopReg('ebp');
        writer.putPopReg('ebx');
        writer.putPopReg('edx');
        writer.putPopReg('ecx');
        writer.putPopReg('eax');
        writer.putPopfx();
        writer.flush()
        return [ writer.offset, p];
    }

    getJumpInstLen(from: NativePointer, to: NativePointer): number {
        return 5; // alway jmp 
    }

    relocCode(from: NativePointer, to: NativePointer, sz: number): [number, ArrayBuffer] {
        let woffset = 0;
        const writer = new X86Writer(to);
        const relocator = new X86Relocator(from,writer);
        const max_cnt=20;
        let cnt = 0;
        let offset=0;
        console.log('relocCode', offset, sz)
        for(let l=0;l<max_cnt;l++){
            offset = relocator.readOne();
            if(relocator.input==null) throw new Error('input in relocator is null')
            console.log(JSON.stringify(relocator.input))
            relocator.writeOne();
            if(offset>=sz)break;
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
flag: sp.add(Process.pointerSize*7).readPointer(),
eax : sp.add(Process.pointerSize*6).readPointer(),
ecx : sp.add(Process.pointerSize*5).readPointer(),
edx : sp.add(Process.pointerSize*4).readPointer(),
ebx : sp.add(Process.pointerSize*3).readPointer(),
ebp : sp.add(Process.pointerSize*2).readPointer(),
esi : sp.add(Process.pointerSize*1).readPointer(),
edi : sp.add(Process.pointerSize*0).readPointer(),
    };
}
