
'use strict';

import { ArmInlineHooker } from "./ArmInlineHooker";
import { Arm64InlineHooker } from "./Arm64InlineHooker";
import { X86InlineHooker } from "./x86InlineHooker";
import { X64InlineHooker } from "./x64InlineHooker";


const inlineHookerFactory = (hook_ptr:NativePointer, hook_fun_ptr:NativePointer, para1: NativePointer, trampoline_ptr?:NativePointer, )=>{
    let arch = Process.arch;
    if(arch == 'arm') {
        console.log('use ArmInlineHooker')
        return new ArmInlineHooker(hook_ptr, hook_fun_ptr, para1, trampoline_ptr)
    }
    else if(arch == 'arm64'){
        console.log('use Arm64InlineHooker')
        return new Arm64InlineHooker(hook_ptr,hook_fun_ptr, para1, trampoline_ptr)
    }
    else if(arch == 'ia32'){
        console.log('use X86InlineHooker')
        return new X86InlineHooker(hook_ptr,hook_fun_ptr, para1,trampoline_ptr)
    }
    else if(arch == 'x64'){
        console.log('use X64InlineHooker')
        return new X64InlineHooker(hook_ptr,hook_fun_ptr, para1,trampoline_ptr)
    }
    else{
        throw `unhandle architecture ${arch}`
    }
}

export const inlineHookPatch = (hook_ptr:NativePointer, hook_fun_ptr:NativePointer, para1:NativePointer, trampoline_ptr?:NativePointer, ):number => {
    let inlineHooker = inlineHookerFactory(hook_ptr, hook_fun_ptr, para1, trampoline_ptr );
    let [trampoline_len, origin_bytes] = inlineHooker.run();
    return trampoline_len;
}
