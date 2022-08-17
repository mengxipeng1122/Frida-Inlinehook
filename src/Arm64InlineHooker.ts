
'use strict';

import { readMemoryArrayBuffer } from "../commutils";
import { InlineHooker } from "./InlineHooker";

// https://developer.arm.com/documentation/ddi0487/latest
// https://developer.arm.com/documentation/ddi0602/latest


//52 #define SH_UTIL_GET_BITS_32(n, high, low) ((uint32_t)((n) << (31u - (high))) >> (31u - (high) + (low)))
let SH_UTIL_GET_BITS_32=(n:number, high:number, low:number):number=>{
    let p ;
    p = ptr(n>>>0);
    p = p .shl(31-high) .and(0xffffffff) .shr(31-high+low);
    return p.toUInt32()
}
//#define SH_UTIL_GET_BITS_64(n, high, low) ((uint64_t)((n) << (63u - (high))) >> (63u - (high) + (low)))
let SH_UTIL_GET_BITS_64=(n:number, high:number, low:number):UInt64=>{
    let ret = new UInt64(n);
    ret = ret.shl(64-high);
    ret = ret.shr(64-high+low)
    return ret;
}
// 53 #define SH_UTIL_GET_BIT_64(n, idx)                ((uint64_t)((n) << (63u - (idx))) >> 63u)
let SH_UTIL_GET_BIT_64=(n:number|UInt64, idx:number):number=>{
    let ret = new UInt64(n);
    ret = ret.shl(63-idx);
    ret = ret.shr(63);
    return ret.and(1).toNumber();
}

//46 #define SH_UTIL_SIGN_EXTEND_64(n, len) \
//47     ((SH_UTIL_GET_BIT_64(n, len - 1) > 0) ? ((n) | (0xFFFFFFFFFFFFFFFF << (len))) : n)
let SH_UTIL_SIGN_EXTEND_64=(n:UInt64|number, len:number):UInt64=>{
    if(typeof n =='number'){ n=new UInt64(n); }
    let bit64 = SH_UTIL_GET_BIT_64(n, len-1);
    if(bit64>0){
        let ret=n; 
        let mask = new UInt64(0xFFFFFFFFFFFFFFFF);
        ret = ret.or(mask.shl(len));
        return ret;
    }
    else {
        return n;
    }
}


enum sh_a64_type_t{
    IGNORED = 0,
    B,
    B_COND,
    BL,
    ADR,
    ADRP,
    LDR_LIT_32,
    LDR_LIT_64,
    LDRSW_LIT,
    PRFM_LIT,
    LDR_SIMD_LIT_32,
    LDR_SIMD_LIT_64,
    LDR_SIMD_LIT_128,
    CBZ,
    CBNZ,
    TBZ,
    TBNZ
} sh_a64_type_t;

let sh_a64_get_type = (inst:number): sh_a64_type_t =>{
    let p = ptr(inst);
    
    if      (p.and( 0xFC000000).equals(0x14000000)) return sh_a64_type_t.B;
    else if (p.and( 0xFF000010).equals(0x54000000)) return sh_a64_type_t.B_COND;
    else if (p.and( 0xFC000000).equals(0x94000000)) return sh_a64_type_t.BL;
    else if (p.and( 0x9F000000).equals(0x10000000)) return sh_a64_type_t.ADR;
    else if (p.and( 0x9F000000).equals(0x90000000)) return sh_a64_type_t.ADRP;
    else if (p.and( 0xFF000000).equals(0x18000000)) return sh_a64_type_t.LDR_LIT_32;
    else if (p.and( 0xFF000000).equals(0x58000000)) return sh_a64_type_t.LDR_LIT_64;
    else if (p.and( 0xFF000000).equals(0x98000000)) return sh_a64_type_t.LDRSW_LIT;
    else if (p.and( 0xFF000000).equals(0xD8000000)) return sh_a64_type_t.PRFM_LIT;
    else if (p.and( 0xFF000000).equals(0x1C000000)) return sh_a64_type_t.LDR_SIMD_LIT_32;
    else if (p.and( 0xFF000000).equals(0x5C000000)) return sh_a64_type_t.LDR_SIMD_LIT_64;
    else if (p.and( 0xFF000000).equals(0x9C000000)) return sh_a64_type_t.LDR_SIMD_LIT_128;
    else if (p.and( 0x7F000000).equals(0x34000000)) return sh_a64_type_t.CBZ;
    else if (p.and( 0x7F000000).equals(0x35000000)) return sh_a64_type_t.CBNZ;
    else if (p.and( 0x7F000000).equals(0x36000000)) return sh_a64_type_t.TBZ;
    else if (p.and( 0x7F000000).equals(0x37000000)) return sh_a64_type_t.TBNZ;
    else return sh_a64_type_t.IGNORED;
}

let sh_a64_get_rewrite_inst_len = (inst:number):number=>{
    let typ    = sh_a64_get_type(inst);
    let map: Record<sh_a64_type_t, number> = {

        [sh_a64_type_t.IGNORED                                  ]:   4 ,      
        [sh_a64_type_t.B                                        ]:  20 ,    
        [sh_a64_type_t.B_COND                                   ]:  28 ,    
        [sh_a64_type_t.BL                                       ]:  20 ,    
        [sh_a64_type_t.ADR                                      ]:  16 ,    
        [sh_a64_type_t.ADRP                                     ]:  16 ,    
        [sh_a64_type_t.LDR_LIT_32                               ]:  20 ,    
        [sh_a64_type_t.LDR_LIT_64                               ]:  20 ,    
        [sh_a64_type_t.LDRSW_LIT                                ]:  20 ,    
        [sh_a64_type_t.PRFM_LIT                                 ]:  28 ,    
        [sh_a64_type_t.LDR_SIMD_LIT_32                          ]:  28 ,    
        [sh_a64_type_t.LDR_SIMD_LIT_64                          ]:  28 ,    
        [sh_a64_type_t.LDR_SIMD_LIT_128                         ]:  28 ,    
        [sh_a64_type_t.CBZ                                      ]:  24 ,    
        [sh_a64_type_t.CBNZ                                     ]:  24 ,    
        [sh_a64_type_t.TBZ                                      ]:  24 ,    
        [sh_a64_type_t.TBNZ                                     ]:  24 ,    
    };
    return map[typ];
}

let sh_a64_rewrite_b = (buf: NativePointer, inst: number, pc: NativePointer, typ: sh_a64_type_t): number => {
    let imm64;
    if (typ == sh_a64_type_t.B_COND) {
        let imm19 = SH_UTIL_GET_BITS_32(inst, 23, 5);
        imm64 = SH_UTIL_SIGN_EXTEND_64(imm19 << 2, 21);
    } else {
        let imm26 = SH_UTIL_GET_BITS_32(inst, 25, 0);
        imm64 = SH_UTIL_SIGN_EXTEND_64(imm26 << 2, 28);
    }
    let addr = pc.add(imm64);

    let offset = 0;
    {
        if (typ == sh_a64_type_t.B_COND) {
            buf.add(offset).writeU32((inst & 0xFF00001F) | 0x40); offset+=4; // B.<cond> #8
            buf.add(offset).writeU32(0x14000006);                                 offset+=4; // B #24
        }
        buf.add(offset).writeU32(0x58000051); offset+=4; // LDR X17, #8
        buf.add(offset).writeU32(0x14000003); offset+=4; // B #12
    }
    {
        buf.add(offset).writePointer(addr); offset += Process.pointerSize;
    }
    {
        if (typ == sh_a64_type_t.BL) {
            buf.add(offset).writeU32(0xD63F0220);    offset+=4; // BLR X17
        }
        else {
            buf.add(offset).writeU32(0xD61F0220);    offset+=4; // BR X17
        }
    }
    return offset;                         // 20 or 28
}

let sh_a64_rewrite_adr=(buf:NativePointer, inst:number, pc:NativePointer, typ:sh_a64_type_t):number=> {
    let xd = SH_UTIL_GET_BITS_32(inst, 4, 0);
    let immlo = SH_UTIL_GET_BITS_32(inst, 30, 29);
    let immhi = SH_UTIL_GET_BITS_32(inst, 23, 5);
    let addr;
    if (typ == sh_a64_type_t.ADR){
        addr = pc .add( SH_UTIL_SIGN_EXTEND_64((immhi << 2) | immlo, 21));
    }
    else { // ADRP
        //addr = (pc .and(0xFFFFFFFFFFFFF000)) + SH_UTIL_SIGN_EXTEND_64((immhi << 14u) | (immlo << 12u), 33u);
        let imm = (immhi<<14) | (immlo<<12);
        let imm_ext = SH_UTIL_SIGN_EXTEND_64(imm,33);
        addr = pc.and(0xFFFFFFFFFFFFF000).add(imm_ext);
    }

    buf.add(0x00).writeU32(0x58000040 | xd);    // LDR Xd, #8
    buf.add(0x04).writeU32(0x14000003);         // B #12
    buf.add(0x08).writePointer(addr);
    return 16;
}

let sh_a64_rewrite_ldr=(buf:NativePointer,    inst:number, pc:NativePointer, typ:sh_a64_type_t):number=> {
    let rt      = SH_UTIL_GET_BITS_32(inst, 4, 0);
    let imm19   = SH_UTIL_GET_BITS_32(inst, 23, 5);
    let offset  = SH_UTIL_SIGN_EXTEND_64((imm19 << 2), 21);
    let addr    = pc.add( offset);

    if (typ == sh_a64_type_t.LDR_LIT_32 || typ == sh_a64_type_t.LDR_LIT_64 || typ == sh_a64_type_t.LDRSW_LIT) {
        buf.add(4*0).writeU32( 0x58000060 | rt);    // LDR Xt, #12
        if (typ == sh_a64_type_t.LDR_LIT_32){
            buf.add(4*1).writeU32(0xB9400000 | rt | (rt << 5));    // LDR Wt, [Xt]
        }else if (typ == sh_a64_type_t.LDR_LIT_64){
            buf.add(4*1).writeU32(0xF9400000 | rt | (rt << 5));    // LDR Xt, [Xt]
        }else{
            // LDRSW_LIT
            buf.add(4*1).writeU32(0xB9800000 | rt | (rt << 5));    // LDRSW Xt, [Xt]
        }
        buf.add(4*2).writeU32(0x14000003);                                            // B #12
        buf.add(4*3).writePointer(addr);
        return 20;
    } else {
        buf.add(4*0).writeU32(0xA93F47F0);              // STP X16, X17, [SP, -0x10]
        buf.add(4*1).writeU32(0x58000091);              // LDR X17, #16
        if (typ == sh_a64_type_t.PRFM_LIT){
            buf.add(4*2).writeU32(0xF9800220 | rt);     // PRFM Rt, [X17]
        }else if (typ == sh_a64_type_t.LDR_SIMD_LIT_32){
            buf.add(4*2).writeU32(0xBD400220 | rt);     // LDR St, [X17]
        }else if (typ == sh_a64_type_t.LDR_SIMD_LIT_64){
            buf.add(4*2).writeU32(0xFD400220 | rt);     // LDR Dt, [X17]
        }else{
            // LDR_SIMD_LIT_128
            buf.add(4*2).writeU32(0x3DC00220 | rt);     // LDR Qt, [X17]
        }
        buf.add(4*3).writeU32(    0xF85F83F1);          // LDR X17, [SP, -0x8]
        buf.add(4*4).writeU32(    0x14000003);          // B #12
        buf.add(4*5).writePointer(addr);
        return 28;
    }
}

let sh_a64_rewrite_cb = (buf:NativePointer, inst:number, pc:NativePointer, ):number=>{
    let imm19 = SH_UTIL_GET_BITS_32(inst, 23, 5);
    let offset = SH_UTIL_SIGN_EXTEND_64((imm19 << 2), 21);
    let addr = pc .add( offset);

    buf.add(4*0).writeU32(inst & 0xFF00001F | 0x40);    // CB(N)Z Rt, #8
    buf.add(4*1).writeU32(0x14000005);                  // B #20
    buf.add(4*2).writeU32(0x58000051);                  // LDR X17, #8
    buf.add(4*3).writeU32(0xd61f0220);                  // BR X17
    buf.add(4*4).writePointer(addr);
    return 24;
}

let sh_a64_rewrite_tb = (buf:NativePointer, inst:number, pc:NativePointer):number => {
    let imm14 = SH_UTIL_GET_BITS_32(inst, 18, 5);
    let offset = SH_UTIL_SIGN_EXTEND_64((imm14 << 2), 16);
    let addr = pc .add( offset);

    buf.add(4*0).writeU32((inst & 0xFFF8001F) | 0x40);    // TB(N)Z Rt, #<imm>, #8
    buf.add(4*1).writeU32(0x14000005);                    // B #20
    buf.add(4*2).writeU32(0x58000051);                    // LDR X17, #8
    buf.add(4*3).writeU32(0xd61f0220);                                     // BR X17
    buf.add(4*4).writePointer(addr);
    return 24;
}

export let    sh_a64_rewrite=(buf:NativePointer, inst:number, pc:NativePointer ):number=> {
    let typ = sh_a64_get_type(inst);
    //console.log(`a64 rewrite: typ ${typ}, inst ${ptr(inst)} `);

    switch(typ) {
        case sh_a64_type_t.B            :
        case sh_a64_type_t.B_COND       :
        case sh_a64_type_t.BL           :
            return sh_a64_rewrite_b(buf, inst, pc, typ);

        case sh_a64_type_t. ADR         :
        case sh_a64_type_t. ADRP        :
            return sh_a64_rewrite_adr(buf, inst, pc, typ);

        case sh_a64_type_t.LDR_LIT_32           :
        case sh_a64_type_t.LDR_LIT_64           :
        case sh_a64_type_t.LDRSW_LIT            :
        case sh_a64_type_t.PRFM_LIT             :
        case sh_a64_type_t.LDR_SIMD_LIT_32      :
        case sh_a64_type_t.LDR_SIMD_LIT_64      :
        case sh_a64_type_t.LDR_SIMD_LIT_128     :
            return sh_a64_rewrite_ldr(buf, inst, pc, typ);

        case sh_a64_type_t. CBZ :
        case sh_a64_type_t. CBNZ:
            return sh_a64_rewrite_cb(buf, inst, pc);

        case sh_a64_type_t. TBZ :
        case sh_a64_type_t. TBNZ:
            return sh_a64_rewrite_tb(buf, inst, pc);

        default:
            buf.writeU32(inst);
            return 4;
    }

}

export class Arm64InlineHooker extends InlineHooker{
    putPrecode(p:NativePointer):[number, NativePointer] {
        let offset=0;
        {
            // write hook_fun_ptr
            p.add(offset).writePointer(this.hook_fun_ptr); offset += Process.pointerSize;
            // write arg1
            p.add(offset).writePointer(this.para1); offset += Process.pointerSize;
            // write precode
        }
        let trampolineCodeAddr = p.add(offset);
        {
            const writer = new Arm64Writer(trampolineCodeAddr);
            writer.putPushAllXRegisters();                            
            writer.putMovRegReg('x1','sp');                         
            writer.putBytes([ 0x80, 0xfd, 0xff, 0x58]);    // 0x58: ldr    x0, trampoline_ptr.add(0x08)
            writer.putBytes([ 0x29, 0xfd, 0xff, 0x58]);    // 0x5c: ldr    x9, trampoline_ptr.add(0x00)
            writer.putBlrReg('x9');                                         
            writer.putPopAllXRegisters();                             
            writer.flush();
            offset += writer.offset
        }
        return [offset, trampolineCodeAddr];
    }
    
    relocCode(from:NativePointer, to:NativePointer, sz:number):[number, ArrayBuffer] {
        let ioff=0;
        let offset = 0;
        for( let t=0;t<InlineHooker.max_code_cnt; t++) {
                if(ioff>=sz) break;
                let iaddr = from.add(ioff)
                let oaddr = to.add(offset);
                let inst = iaddr.readU32();
                offset+= sh_a64_rewrite(oaddr,inst,iaddr);
                ioff+=4;
        }
        let origin_bytes = readMemoryArrayBuffer(from, sz)
        return [offset, origin_bytes]
    }
    
    
    canBranchDirectlyBetween(from:NativePointer, to:NativePointer):boolean {
        return new Arm64Writer(ptr(0)).canBranchDirectlyBetween(from, to);
    }
    
    getJumpInstLen(from:NativePointer, to:NativePointer):number{
        if(this.canBranchDirectlyBetween(from, to)) return 4;
        else return 0x10;
    }
    
    putJumpCode(from:NativePointer, to:NativePointer):number {
        let code = from;
        const writer = new Arm64Writer(code);
        if(this.canBranchDirectlyBetween(from,to)){
            writer.putBImm(to);
            writer.flush();
            return writer.offset;
        }
        else{
            writer.putBytes([ 0x50, 0x00, 0x00, 0x58]);    // ldr x16, #8
            writer.putBrReg('x16');
            writer.flush();
            from.add(writer.offset).writePointer(to);
            return writer.offset+Process.pointerSize;
        }
    }

    getTrampolineCodeSize():number{
        let ret  = 0x100;
        console.log(`call get trampoline code size ${ret}`)
        return ret;
    }
}


export let getRegs = (sp:NativePointer) =>{
    return    {
        NZCV   :sp.add(Process.pointerSize*1 ).readPointer(),
        X30    :sp.add(Process.pointerSize*0 ).readPointer(),
        X29    :sp.add(Process.pointerSize*3 ).readPointer(),
        X28    :sp.add(Process.pointerSize*2 ).readPointer(),
        X27    :sp.add(Process.pointerSize*5 ).readPointer(),
        X26    :sp.add(Process.pointerSize*4 ).readPointer(),
        X25    :sp.add(Process.pointerSize*7 ).readPointer(),
        X24    :sp.add(Process.pointerSize*6 ).readPointer(),
        X23    :sp.add(Process.pointerSize*9 ).readPointer(),
        X22    :sp.add(Process.pointerSize*8 ).readPointer(),
        X21    :sp.add(Process.pointerSize*11).readPointer(),
        X20    :sp.add(Process.pointerSize*10).readPointer(),
        X19    :sp.add(Process.pointerSize*13).readPointer(),
        X18    :sp.add(Process.pointerSize*12).readPointer(),
        X17    :sp.add(Process.pointerSize*15).readPointer(),
        X16    :sp.add(Process.pointerSize*14).readPointer(),
        X15    :sp.add(Process.pointerSize*17).readPointer(),
        X14    :sp.add(Process.pointerSize*16).readPointer(),
        X13    :sp.add(Process.pointerSize*19).readPointer(),
        X12    :sp.add(Process.pointerSize*18).readPointer(),
        X11    :sp.add(Process.pointerSize*21).readPointer(),
        X10    :sp.add(Process.pointerSize*20).readPointer(),
        X9     :sp.add(Process.pointerSize*23).readPointer(),
        X8     :sp.add(Process.pointerSize*22).readPointer(),
        X7     :sp.add(Process.pointerSize*25).readPointer(),
        X6     :sp.add(Process.pointerSize*24).readPointer(),
        X5     :sp.add(Process.pointerSize*27).readPointer(),
        X4     :sp.add(Process.pointerSize*26).readPointer(),
        X3     :sp.add(Process.pointerSize*29).readPointer(),
        X2     :sp.add(Process.pointerSize*28).readPointer(),
        X1     :sp.add(Process.pointerSize*31).readPointer(),
        X0     :sp.add(Process.pointerSize*30).readPointer(),
    };
}
