
'use strict';

//////////////////////////////////////////////////
// common utils, do not depends with os and arch
export const dumpMemory=(p:NativePointer, l?:number):void=> {
    if (l == undefined) l = 0x20;
    console.log(hexdump(p, {
        offset: 0,
        length: l,
        header: true,
        ansi: false
    }));
    return;
};

export const typedArrayToBuffer=(array: Uint8Array):ArrayBuffer=> {
    return array.buffer.slice(array.byteOffset, array.byteLength + array.byteOffset) as ArrayBuffer;
}

export const alignNum=(n:number, align:number):number=>{
    return Math.floor((n+align-1)/align) *align;
}

export const showAsmCode=(p:NativePointer, count?: number):void=>{
    if (count == undefined) count = 5;
    let addr = p;
    for(var i = 0; i<count; i++){
        const inst = Instruction.parse(addr);
        console.log(addr, inst.toString())
        addr = addr.add(inst.size);
    }
}

export const findInstructInso=(wantinst:string, soname:string):void=>{
    console.log('find', wantinst, 'in', soname)
    let m = Process.getModuleByName(soname);
    let addr = m.base;
    do{
        try{
            let inst = Instruction.parse(addr);
            if(inst.mnemonic.toLowerCase().includes(wantinst)){
                console.log(addr, inst.toString(),'@',m.name, addr.sub(m.base));
            }
            addr=addr.add(inst.size);
        }
        catch{
            addr=addr.add(2);
        }
    } while(addr.compare(m.base.add(m.size))<0);
    console.log('end find', soname)
}

export const showBacktrace=(thiz:InvocationContext, sobase?:NativePointer, tstr?:string):void => {
    var callbacktrace = Thread.backtrace(thiz.context,Backtracer.ACCURATE);
    console.log(tstr!=undefined?tstr:"", ' callbacktrace ' + callbacktrace);
    callbacktrace.forEach(c=>{
        let sym =DebugSymbol.fromAddress(c);
        console.log(tstr!=undefined?tstr:"", c, "(", sobase!=undefined?c.sub(sobase):"",")",'=>', sym);
    })
}

export const resolveSymbol=(name:string, libs?:(string|null)[]):NativePointer=>{
    let resolved=false;
    let symbolAddress:NativePointer;
    if(libs==undefined){
        libs=[null];
    }else{
        libs.push(null);
    }
    let address : NativePointer|null = null;
    libs.forEach(lib=>{
        if(address!=null)return;
        address=Module.findExportByName(lib,name);
    })
    if(address!=null) return address;
    throw new Error(`can not find symbol ${name}`)
}

export const getU32BigEndian=(p:NativePointer):number=>{
    let ret = 0;
    ret +=  (p.add(0).readU8() << 0x18)
    ret +=  (p.add(1).readU8() << 0x10)
    ret +=  (p.add(2).readU8() << 0x08)
    ret +=  (p.add(3).readU8() << 0x00)
    return ret>>>0;
}

export const getU16BigEndian=(p:NativePointer):number=>{
    let ret = 0;
    ret +=  (p.add(0).readU8() << 0x08)
    ret +=  (p.add(1).readU8() << 0x00)
    return ret>>>0;
}

export const getU8BigEndian=(p:NativePointer):number=>{
    let ret = 0;
    ret +=  (p.add(0).readU8() << 0x00)
    return ret>>>0;
}

export const getInetAddrInfo=(addrinfo:NativePointer):string=>{
    if(addrinfo.isNull()) throw `addreinfo is null`
    let af = addrinfo.add(0).readU16(); if(af!=2) throw `af is not 2`
    let a0 = addrinfo.add(4).readU8();
    let a1 = addrinfo.add(5).readU8();
    let a2 = addrinfo.add(6).readU8();
    let a3 = addrinfo.add(7).readU8();
    let port  = addrinfo.add(2).readU16();
    return `${a0}.${a1}.${a2}.${a3}:${port}`;
}

export const dumpSoSymbols=(soname:string):void=>{
    let m  = Process.getModuleByName(soname);
    if(!m) throw `can not found so ${soname}`;
    console.log(`found ${soname}`)
    console.log(JSON.stringify(m));
    m.enumerateExports()
        .forEach(e=>{
            let ee = Object.create(e);
            ee = {...e, offset : e.address.sub(m.base)};
            console.log(JSON.stringify(ee))
        })
    m.enumerateSymbols()
        .forEach(s=>{
            let ss = Object.create(s);
            ss = {...s, offset : s.address.sub(m.base)};
            console.log(JSON.stringify(ss))
        })
}

type SYMBOLINFO= {
    address :NativePointer; 
    name    :string;
    type    :string;
    offset  :NativePointer;
};
type SYMBOLSINFO= {[key:string]:SYMBOLINFO};
export const getSoSymbols = (m:Module):SYMBOLSINFO=>{
    let symbols:SYMBOLSINFO ={};
    console.log(JSON.stringify(m));
    m.enumerateExports()
        .forEach(e=>{
            let ee = Object.create(e);
            ee = {...e, offset : e.address.sub(m.base)};
            symbols[e.name] = ee;
        })
    m.enumerateSymbols()
        .forEach(s=>{
            let ss = Object.create(s);
            ss = {...s, offset : s.address.sub(m.base)};
            symbols[s.name] = ss;
        })
    return symbols;
}


export const runFunWithExceptHandling = (f:()=>void, cb?:(pe:Error)=>void):void=>{
    const handleExceptionContetx = (e:Error):void=>{
        if ((e as any).context != undefined) {
            let context = (e as any).context;
            console.log('called from:\n' +
                Thread.backtrace(context, Backtracer.ACCURATE)
                    .map(DebugSymbol.fromAddress).join('\n') + '\n');
            let pc = context.pc;
            console.log('pc', pc)
            let range = Process.getRangeByAddress(pc);
            console.log(JSON.stringify(range))
            console.log(pc, pc.sub(range.base))
        }
    }

    try{
        f();
    }
    catch(_e){
        // show errors
        let e:Error= _e as Error;
        console.log('error occur', typeof(_e))
        console.log(e)
        console.log(JSON.stringify(e))
        handleExceptionContetx(e);
        if(cb!=undefined) cb(e)
    }
}

export const converUInt32ToFloat = (u:number):number=>{
    let buf = new ArrayBuffer(4);
    let uview = new Int32Array(buf);
    let fview  = new Float32Array(buf);
    uview[0] = u; 
    let f = fview[0];
    return f;
}

export const isHex = (h:string):boolean=>{
    var a = parseInt(h, 16);
    return (a.toString(16) === h)
}

export const awaitForCondition = (cond:()=>boolean, callback:()=>void, interval?:number):void =>{
    if(interval==undefined) interval=.1;
    var i = setInterval(function () {
        let c = cond();
        if (c) {
            clearInterval(i);
            callback();
        }
    }, interval);
}

export const awaitForLibraryLoaded = (lib:string, callback:()=>void):void=> {
    awaitForCondition(()=>{
      var addr = Module.findBaseAddress(lib);
      return addr!=null;
    }, callback);
}

export const getStringSet=(param:string|string[]):Set<string> =>{
    if(typeof(param) =='string') { return new Set<string>([param]); }
    else return new Set<string>(param);
}

export const exit = ():void=>{
    console.log('##########EXIT##########')
}

export const _frida_log_callback =  new NativeCallback(function(sp:NativePointer){
    console.log(sp.readUtf8String());
}, 'void', ['pointer']);

export const _frida_err_callback =  new NativeCallback(function(sp:NativePointer){
    console.log(sp.readUtf8String());
    new NativeFunction(Module.getExportByName(null,'exit'),'int',['int'])(-9);
    throw 'err occured and exit';
}, 'void', ['pointer']);

export const _frida_hexdump_callback =  new NativeCallback(function(sp:NativePointer, sz:number){
    dumpMemory(sp, sz);
}, 'void', ['pointer','uint']);


export const logWithFileNameAndLineNo = (msg:string)=>{
    let getErrorObject = function(){
        try{throw Error('');} catch(err) {return err;}
    }
    let err = getErrorObject() as Error;
    const caller_line = err.stack!=undefined?err.stack.split("\n")[3] : "unknow line";
    // remove `at `
    let index = caller_line?.indexOf('at ');
    let final_caller_line = (index>=0) ?caller_line.slice(index+3) : caller_line;
    console.log(final_caller_line, ":", msg)
}

export const getPyCodeFromMemory=(p:NativePointer, sz:number):string=>{
    let pycode = "";
    pycode += `(${p}, [`
    let bs = p.readByteArray(sz)
    if(bs==null) throw `can not read at ${sz}`
    pycode += new Uint8Array(bs).join(',')
    pycode += ']), '
    console.log(pycode)
    return pycode;
}

export const readMemoryArrayBuffer=(p:NativePointer, sz?:number):ArrayBuffer=>{
    if(sz==undefined) sz = 0x10;
    let ab = p.readByteArray(sz);
    if(ab==null) throw new Error(`read ${sz} bytes from ${p} failed`)
    return ab;
}


