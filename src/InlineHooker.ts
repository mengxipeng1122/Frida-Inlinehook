
'use strict';

import {readMemoryArrayBuffer} from '../commutils'

export abstract class InlineHooker
{
    hook_fun_ptr        : NativePointer;
    trampoline_ptr      : NativePointer;
    hook_ptr            : NativePointer;
    para1               : NativePointer;
    constructor(hook_ptr:NativePointer, trampoline_ptr:NativePointer, hook_fun_ptr:NativePointer, para1:NativePointer){
        this.hook_ptr       = hook_ptr;
        this.trampoline_ptr = trampoline_ptr;
        this.hook_fun_ptr   = hook_fun_ptr;
        this.para1          = para1;
    }

    static max_code_cnt= 5;
    static max_trampoline_len = 0x200;

    putPrecode(p:NativePointer):[number, NativePointer] {
        throw new Error(`please implement putPrecode function ${JSON.stringify(this)}`);
    }

    relocCode(from:NativePointer, to:NativePointer, sz:number):[number, ArrayBuffer] {
        throw new Error(`please implement relocCode function ${JSON.stringify(this)}`);
    }

    relocCodeByFrida(from:NativePointer, to:NativePointer, sz:number):[number, ArrayBuffer] {
        throw new Error(`please implement relocCodeByFrida function ${JSON.stringify(this)}`);
    }

    putJumpCode(from:NativePointer, to:NativePointer):number {
        throw new Error(`please implement putJumpCode function ${JSON.stringify(this)}`);
    }

    canBranchDirectlyBetween(from:NativePointer, to:NativePointer):boolean {
        throw new Error(`please implement canBranchDirectlyBetween function ${JSON.stringify(this)}`);
    }

    getJumpInstLen(from:NativePointer, to:NativePointer):number{
        throw new Error(`please implement getJumpInstLen function ${JSON.stringify(this)}`);
    }

    run():[number, ArrayBuffer]{
        if(InlineHooker.hasHooked(this.hook_ptr)) { throw new Error(`${this.hook_ptr} has hooked, does not rebook`) }
        let origin_bytes:ArrayBuffer=new ArrayBuffer(0)
        let offset = 0;
        let relocsz=0;
        let trampolineCodeAddr = ptr(0);
        // write trampoline code 
        Memory.patchCode(this.trampoline_ptr, InlineHooker.max_trampoline_len, code=>{
            let sz=0;
            [ sz, trampolineCodeAddr] = this.putPrecode(code.add(offset)); offset += sz;
            // relocate code 
            relocsz = this.getJumpInstLen(this.hook_ptr, trampolineCodeAddr);
            [sz, origin_bytes] = this.relocCode(this.hook_ptr, code.add(offset), relocsz);
            offset += sz;
            // write jump back code 
            let origin_inst_len = origin_bytes.byteLength;
            sz = this.putJumpCode(code.add(offset), this.hook_ptr.add(origin_inst_len)); offset += sz;
        });  
        // write jump code at hook_ptr
        let jumpsz = this.getJumpInstLen(this.hook_ptr, trampolineCodeAddr);
        origin_bytes = readMemoryArrayBuffer(this.hook_ptr, jumpsz)
        Memory.patchCode(this.hook_ptr, jumpsz, code=>{
            let sz = this.putJumpCode(code, trampolineCodeAddr)
        })
        InlineHooker.all_inline_hooks[this.hook_ptr.toString()]= {
            hook_ptr        : this.hook_ptr,
            hook_fun_ptr    : this.hook_fun_ptr,
            origin_bytes    : origin_bytes,
        }
        return [offset, origin_bytes];
    }

    static all_inline_hooks:{[key:string]:{
            origin_bytes    :   ArrayBuffer,
            hook_ptr        :   NativePointer,
            hook_fun_ptr    :   NativePointer,
    }} = { };

    static hasHooked = (hook_ptr:NativePointer):boolean=>{
        return hook_ptr.toString() in InlineHooker.all_inline_hooks;
    }

    static restoreAllInlineHooks=()=>{
        let hooks = InlineHooker.all_inline_hooks;
        Object.keys(hooks).forEach(k=>{
            let v = hooks[k]
            if (v.origin_bytes!=null){
                let bs = v.origin_bytes;
                let p = v.hook_ptr;
                let sz = bs.byteLength;
                Memory.patchCode(p,sz, code=>{
                    code.writeByteArray(bs)
                })
            }
        })
    }

};
