

import { InlineHooker } from './src/InlineHooker';
import { inlineHookPatch } from './src/InlineHookerFactory';
import * as ArmInlineHooker from './src/ArmInlineHooker'
import * as Arm64InlineHooker from './src/Arm64InlineHooker'
import * as X86InlineHooker from './src/x86InlineHooker'
import * as X64InlineHooker from './src/x64InlineHooker'
import * as exe_arm     from './soinfos/exe_arm'
import * as exe_thumb   from './soinfos/exe_thumb'
import * as exe_arm64   from './soinfos/exe_arm64'
import * as exe_x86     from './soinfos/exe_x86'
import * as exe_x64     from './soinfos/exe_x64'
import { dumpMemory, readMemoryArrayBuffer } from './commutils';

         
const dumpMemoryToPyCode = (mem:{[key:string]:{ p:NativePointer, sz:number}})=>{
    let code = ``;
    code += `patchInfos = { \n`
    Object.keys(mem).forEach(k=>{
        let v   = mem[k];
        let p   = v.p
        let sz  = v.sz
        let bs = new Uint8Array(readMemoryArrayBuffer(p,sz))
        code += `
    '${k}' : (
${p} , bytes([ ${bs.join(',')} ])
    ),
`
    }) 
    code += `}`;
    console.log(code)
    return code;
}


let testExeThumb = (moduleName:string)=>{
    let m = Process.getModuleByName(moduleName);
    let trampoline_ptr = m.base.add(exe_thumb.info.loads[0].virtual_size);
    const hook_fun_ptr  = new NativeCallback(function(para1:NativePointer, sp:NativePointer):number{
        console.log(`call hook_fun with ${sp} and ${para1}`)
        console.log('regs',  JSON.stringify(ArmInlineHooker.getRegs(sp)))
        return 1;
    },'int',['pointer','pointer']);
    {
        let hook_ptr = m.base.add(0x6df);
        inlineHookPatch(hook_ptr, hook_fun_ptr, hook_ptr, );
        let patch = InlineHooker.all_inline_hooks[hook_ptr.toString()];
        dumpMemoryToPyCode({
            'hook'      : { p : patch.hook_ptr.and(~1),     sz: 0x20   },
            'trampoline': { p : patch.trampoline_ptr,       sz: 0x100  },
            'hook_fun'  : { p : patch.hook_fun_ptr,         sz: 0x20   },
        })
    }
    {
        let hook_ptr = m.base.add(0x6ed);
        inlineHookPatch(hook_ptr, hook_fun_ptr, hook_ptr, );
    }
    console.log(JSON.stringify(InlineHooker.all_inline_hooks))

}

let testExeArm =  (moduleName:string)=>{
    let m = Process.getModuleByName(moduleName);
    let trampoline_ptr = m.base.add(exe_arm.info.loads[0].virtual_size);
    let hook_ptr = m.base.add(0x6e8);
    const hook_fun_ptr  = new NativeCallback(function(para1:NativePointer, sp:NativePointer):number{
        console.log(`call hook_fun with ${sp} and ${para1}`)
        console.log('regs',  JSON.stringify(ArmInlineHooker.getRegs(sp)))
        return 1;
    },'int',['pointer','pointer']);
    inlineHookPatch(hook_ptr, hook_fun_ptr, hook_ptr );
    let patch = InlineHooker.all_inline_hooks[hook_ptr.toString()];
    dumpMemoryToPyCode({
        'hook'      : { p : patch.hook_ptr,              sz: 0x20   },
        'trampoline': { p : patch.trampoline_ptr,       sz: 0x100  },
        'hook_fun'  : { p : patch.hook_fun_ptr,         sz: 0x20   },
    })
}

let testExeArm64 = (moduleName:string)=>{
    let m = Process.getModuleByName(moduleName);
    let trampoline_ptr = m.base.add(exe_arm64.info.loads[0].virtual_size);
    let hook_ptr = m.base.add(0x904);
    if(false) {
        dumpMemory(hook_ptr)
        Interceptor.attach(hook_ptr,{
            onEnter:function(args) {
                console.log(args[0])
            }
        })
        Thread.sleep(.1)
        dumpMemory(hook_ptr)
    }
    if(true){
        let funname = 'fflush'
        let funp = Module.getExportByName(null, funname);
        console.log(`${funname} : ${funp}`)
    }
    const hook_fun_ptr  = new NativeCallback(function(para1:NativePointer, sp:NativePointer):number{
        console.log(`call hook_fun with ${sp} and ${para1}`)
        console.log('regs',  JSON.stringify(Arm64InlineHooker.getRegs(sp)))
        return 1;
    },'int',['pointer','pointer']);
    inlineHookPatch(hook_ptr, hook_fun_ptr, hook_ptr );
    let patch = InlineHooker.all_inline_hooks[hook_ptr.toString()];
    dumpMemoryToPyCode({
        'hook'      : { p : patch.hook_ptr,             sz: 0x20   },
        'trampoline': { p : patch.trampoline_ptr,       sz: 0x100  },
        'hook_fun'  : { p : patch.hook_fun_ptr,         sz: 0x20   },
    })
}

let testExeX86 = (moduleName:string)=>{
    let m = Process.getModuleByName(moduleName);
    let seg = exe_x86.info.loads[1]
    let trampoline_ptr = m.base.add(seg.virtual_address).add(seg.virtual_size)
    let hook_ptr = m.base.add(0x1287);
    const hook_fun_ptr  = new NativeCallback(function(para1:NativePointer, sp:NativePointer):number{
        console.log(`call hook_fun with ${sp} and ${para1}`)
        console.log('regs',  JSON.stringify(X86InlineHooker.getRegs(sp)))
        return 1;
    },'int',['pointer','pointer'],'fastcall'); // use fastcall
    inlineHookPatch(hook_ptr, hook_fun_ptr, hook_ptr );
}

let testExeX64 = (moduleName:string)=>{
    let m = Process.getModuleByName(moduleName);
    let seg = exe_x64.info.loads[1]
    let trampoline_ptr = m.base.add(seg.virtual_address).add(seg.virtual_size)
    let hook_ptr = m.base.add(0x11fc);
    const hook_fun_ptr  = new NativeCallback(function(para1:NativePointer, sp:NativePointer):number{
        console.log(`call hook_fun with ${para1} and ${sp}`)
        console.log('regs',  JSON.stringify(X64InlineHooker.getRegs(sp)))
        return 1;
    },'int',['pointer','pointer']);
    inlineHookPatch(hook_ptr, hook_fun_ptr, hook_ptr );
    let patch = InlineHooker.all_inline_hooks[hook_ptr.toString()];
    dumpMemoryToPyCode({
        'hook'      : { p : patch.hook_ptr,             sz: 0x20   },
        'trampoline': { p : patch.trampoline_ptr,       sz: 0x100  },
        'hook_fun'  : { p : patch.hook_fun_ptr,         sz: 0x20   },
    })
}

const test = ()=>{
    // replace printf function to print more information
    if(true){
        let printf = new NativeFunction(Module.getExportByName(null,'printf'), 'int',['pointer']);
        Interceptor.replace(printf, new NativeCallback(function(fmt:NativePointer, i:number ){
            let s = fmt.readUtf8String();
            console.log(`call printf with ${fmt} ${s} ${i}`);
            return 0;
        },'int', ['pointer','int']))
    }

    let testFunMap : {[key:string]:
        {
            fun     : (m:string)=>void,
            arch    : string,
        }
    } = {
        exe_arm     : { fun : testExeArm,       arch :'arm'     },
        exe_thumb   : { fun : testExeThumb,     arch :'arm'     },
        exe_arm64   : { fun : testExeArm64,     arch :'arm64'   },
        exe_x64     : { fun : testExeX64,       arch :'x64'     },
        exe_x86     : { fun : testExeX86,       arch :'ia32'    },
    }
    let foundModule = false;
    Object.keys(testFunMap)
        .forEach(name=>{
            if(foundModule) return;
            let m = Process.findModuleByName(name)
            if(m!=null) {
                let f = testFunMap[name].fun;
                let arch = testFunMap[name].arch;
                if(Process.arch!=arch) throw new Error(`please check test environment ${arch} / ${Process.arch}`)
                f(name);
                foundModule = true;
            }
        })
    if(!foundModule) throw new Error(`can not found all modules `)
}

console.log("##################################################")
test();

rpc.exports = {
    init : function(stage, paras){
    },
    dispose: function(){ 
        InlineHooker.restoreAllInlineHooks();
    },
}

