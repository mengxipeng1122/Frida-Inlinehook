
'use strict';

import { readArrayBufferFromMemory } from "./commutils";

export type INLINE_HOOK_TYPE = {
    origin_bytes    :   ArrayBuffer,
    hook_ptr        :   NativePointer,
    hook_fun_ptr    :   NativePointer,
    trampoline_ptr  :   NativePointer,
};


export abstract class InlineHooker
{
    hook_fun_ptr        : NativePointer;
    trampoline_ptr      : NativePointer;
    hook_ptr            : NativePointer;
    para1               : NativePointer;
    constructor(
        hook_ptr:NativePointer, 
        hook_fun_ptr:NativePointer, 
        para1:NativePointer,
        trampoline_ptr?:NativePointer, 
        ){
        this.hook_ptr       = hook_ptr;
        this.hook_fun_ptr   = hook_fun_ptr;
        this.para1          = para1;
        if(trampoline_ptr!=undefined) this.trampoline_ptr = trampoline_ptr;
        else {
            this.trampoline_ptr = InlineHooker.allocTrampolineMem(this.getTrampolineCodeSize())
        }
    }

    static max_code_cnt= 5;
    static max_trampoline_len = 0x100;

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

    getTrampolineCodeSize():number{
        return InlineHooker.max_trampoline_len;
    }

    run():INLINE_HOOK_TYPE{
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
            console.log('orgin_inst', sz, origin_inst_len)
            sz = this.putJumpCode(code.add(offset), this.hook_ptr.add(origin_inst_len)); offset += sz;
        });  
        // write jump code at hook_ptr
        let jumpsz = origin_bytes.byteLength;
        Memory.patchCode(this.hook_ptr, jumpsz, code=>{
            let sz = this.putJumpCode(code, trampolineCodeAddr)
        })
        let newInlineHook =  {
            hook_ptr        : this.hook_ptr,
            hook_fun_ptr    : this.hook_fun_ptr,
            trampoline_ptr  : this.trampoline_ptr,
            origin_bytes    ,
        }
        InlineHooker.all_inline_hooks[this.hook_ptr.toString()]=  newInlineHook;
        return newInlineHook;
    }

    static trampoline_pages_info : {
        pages: NativePointer[],
        last_page_idx : number,
        last_page_offset: number,
    } = {
        pages:[],
        last_page_idx:-1,
        last_page_offset:-1,
    };

    static allocTrampolineMem(sz:number):NativePointer {
        let info = InlineHooker.trampoline_pages_info;
        let p:NativePointer|null=null;
        if(info.last_page_idx>=0){
            if(info.last_page_idx<0) throw new Error(`info is not consistent ${JSON.stringify(info)}`);
            if(info.last_page_offset<0) throw new Error(`info is not consistent ${JSON.stringify(info)}`);
            if(info.last_page_offset+sz<=Process.pageSize) {
                p = info.pages[info.last_page_idx].add(info.last_page_offset);
                info.last_page_offset+=sz;
            }
        }
        if(p==null) {
            info.pages.push(Memory.alloc(Process.pageSize));
            info.last_page_idx = info.pages.length-1;
            p = info.pages[info.last_page_idx];
            info.last_page_offset = sz;
        }
        if(p==null) throw new Error(`alloc trapoline failed`);
        return p;
    }

    static all_inline_hooks:{[key:string]: INLINE_HOOK_TYPE} = {};

    static hasHooked = (hook_ptr:NativePointer):boolean=>{
        return hook_ptr.toString() in InlineHooker.all_inline_hooks;
    }

    static restoreAllInlineHooks=()=>{
        let hooks = InlineHooker.all_inline_hooks;
        Object.keys(hooks).forEach(k=>{
            let v = hooks[k]
            let bs = v.origin_bytes;
            let p = v.hook_ptr;
            let sz = bs.byteLength;
            Memory.patchCode(p,sz, code=>{
                code.writeByteArray(bs)
            })
        })
    }
};
