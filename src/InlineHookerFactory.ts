
'use strict';

import { ArmInlineHooker } from "./ArmInlineHooker";
import { Arm64InlineHooker } from "./Arm64InlineHooker";
import { X86InlineHooker } from "./x86InlineHooker";
import { X64InlineHooker } from "./x64InlineHooker";


const inlineHookerFactory = (hook_ptr:NativePointer, trampoline_ptr:NativePointer, hook_fun_ptr:NativePointer, para1: NativePointer)=>{
    let arch = Process.arch;
    if(arch == 'arm') {
        console.log('use ArmInlineHooker')
        return new ArmInlineHooker(hook_ptr, trampoline_ptr,hook_fun_ptr, para1)
    }
    else if(arch == 'arm64'){
        console.log('use Arm64InlineHooker')
        return new Arm64InlineHooker(hook_ptr, trampoline_ptr,hook_fun_ptr, para1)
    }
    else if(arch == 'ia32'){
        console.log('use X86InlineHooker')
        return new X86InlineHooker(hook_ptr, trampoline_ptr,hook_fun_ptr, para1)
    }
    else if(arch == 'x64'){
        console.log('use X64InlineHooker')
        return new X64InlineHooker(hook_ptr, trampoline_ptr,hook_fun_ptr, para1)
    }
    else{
        throw `unhandle architecture ${arch}`
    }
}

export const inlineHookPatch = (trampoline_ptr:NativePointer, hook_ptr:NativePointer, hook_fun_ptr:NativePointer, para1:NativePointer):number => {
    let inlineHooker = inlineHookerFactory(hook_ptr, trampoline_ptr, hook_fun_ptr, para1);
    let [trampoline_len, origin_bytes] = inlineHooker.run();
    return trampoline_len;
}
