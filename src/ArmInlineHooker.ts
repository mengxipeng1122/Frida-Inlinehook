
'use strict';

import { readArrayBufferFromMemory } from './commutils'
import { InlineHooker } from "./InlineHooker";

const ALIGN_PC = (pc:NativePointer)=>(pc.and(0xFFFFFFFC));

enum INSTRUCTION_TYPE {
    // B <label>
    B1_THUMB16,
    // B <label>
    B2_THUMB16,
    // BX PC
    BX_THUMB16,
    // ADD <Rdn>, PC (Rd != PC, Rn != PC) 
    ADD_THUMB16,
    // MOV Rd, PC
    MOV_THUMB16,
    // ADR Rd, <label>
    ADR_THUMB16,
    // LDR Rt, <label>
    LDR_THUMB16,

    // CB{N}Z <Rn>, <label>
    CB_THUMB16,


    // BLX <label>
    BLX_THUMB32,
    // BL <label>
    BL_THUMB32,
    // B.W <label>
    B1_THUMB32,
    // B.W <label>
    B2_THUMB32,
    // ADR.W Rd, <label>
    ADR1_THUMB32,
    // ADR.W Rd, <label>
    ADR2_THUMB32,
    // LDR.W Rt, <label>
    LDR_THUMB32,
    // TBB [PC, Rm]
    TBB_THUMB32,
    // TBH [PC, Rm, LSL #1]
    TBH_THUMB32,

    // BLX <label>
    BLX_ARM,
    // BL <label>
    BL_ARM,
    // B <label>
    B_ARM,
    // BX PC
    BX_ARM,
    // ADD Rd, PC, Rm (Rd != PC, Rm != PC)
    ADD_ARM,
    // ADR Rd, <label>
    ADR1_ARM,
    // ADR Rd, <label>
    ADR2_ARM,
    // MOV Rd, PC
    MOV_ARM,
    // LDR Rt, <label>
    LDR_ARM,

    UNDEFINE,
};

const getTypeInThumb16 = (instruction:number):INSTRUCTION_TYPE=> {
    let p = ptr(instruction);
    if (p.and(0xF000).compare(0xD000)==0) return INSTRUCTION_TYPE.B1_THUMB16; 
    if (p.and(0xF800).compare(0xE000)==0) return INSTRUCTION_TYPE.B2_THUMB16; 
    if (p.and(0xFFF8).compare(0x4778)==0) return INSTRUCTION_TYPE.BX_THUMB16; 
    if (p.and(0xFF78).compare(0x4478)==0) return INSTRUCTION_TYPE.ADD_THUMB16;
    if (p.and(0xFF78).compare(0x4678)==0) return INSTRUCTION_TYPE.MOV_THUMB16;
    if (p.and(0xF800).compare(0xA000)==0) return INSTRUCTION_TYPE.ADR_THUMB16;
    if (p.and(0xF800).compare(0x4800)==0) return INSTRUCTION_TYPE.LDR_THUMB16;
    if (p.and(0xF500).compare(0xB100)==0) return INSTRUCTION_TYPE.CB_THUMB16; 
    return INSTRUCTION_TYPE.UNDEFINE;
}

const getTypeInThumb32 = (instruction:number):INSTRUCTION_TYPE =>{
    let p = ptr(instruction);
    if (p.and(0xFFF0D000).compare(0xF3B08000)==0) return INSTRUCTION_TYPE.UNDEFINE;   
    if (p.and(0xF800D000).compare(0xF000C000)==0) return INSTRUCTION_TYPE.BLX_THUMB32;
    if (p.and(0xF800D000).compare(0xF000D000)==0) return INSTRUCTION_TYPE.BL_THUMB32; 
    if (p.and(0xF800D000).compare(0xF0008000)==0) return INSTRUCTION_TYPE.B1_THUMB32; 
    if (p.and(0xF800D000).compare(0xF0009000)==0) return INSTRUCTION_TYPE.B2_THUMB32; 
    if (p.and(0xFBFF8000).compare(0xF2AF0000)==0) return INSTRUCTION_TYPE.ADR1_THUMB32;
    if (p.and(0xFBFF8000).compare(0xF20F0000)==0) return INSTRUCTION_TYPE.ADR2_THUMB32;
    if (p.and(0xFF7F0000).compare(0xF85F0000)==0) return INSTRUCTION_TYPE.LDR_THUMB32;
    if (p.and(0xFFFF00F0).compare(0xE8DF0000)==0) return INSTRUCTION_TYPE.TBB_THUMB32;
    if (p.and(0xFFFF00F0).compare(0xE8DF0010)==0) return INSTRUCTION_TYPE.TBH_THUMB32;
    return INSTRUCTION_TYPE.UNDEFINE;
}

const getTypeInArm = (instruction:number):INSTRUCTION_TYPE =>{
    let p = ptr(instruction);
    if (p.and(0xFE000000).compare(0xFA000000)==0)   return   INSTRUCTION_TYPE.BLX_ARM;  
    if (p.and(0x0F000000).compare(0x0B000000)==0)   return   INSTRUCTION_TYPE.BL_ARM;   
    if (p.and(0x0F000000).compare(0x0A000000)==0)   return   INSTRUCTION_TYPE.B_ARM;    
    if (p.and(0x0FF000FF).compare(0x0120001F)==0)   return   INSTRUCTION_TYPE.BX_ARM;   
    if (p.and(0x0FEF0010).compare(0x008F0000)==0)   return   INSTRUCTION_TYPE.ADD_ARM;  
    if (p.and(0x0FFF0000).compare(0x028F0000)==0)   return   INSTRUCTION_TYPE.ADR1_ARM; 
    if (p.and(0x0FFF0000).compare(0x024F0000)==0)   return   INSTRUCTION_TYPE.ADR2_ARM; 
    if (p.and(0x0E5F0000).compare(0x041F0000)==0)   return   INSTRUCTION_TYPE.LDR_ARM;  
    if (p.and(0x0FE00FFF).compare(0x01A0000F)==0)   return   INSTRUCTION_TYPE.MOV_ARM;  
    return INSTRUCTION_TYPE.UNDEFINE;
}

const relocateInstructionInThumb16=(pc:NativePointer, instruction:number, trampoline_instructions:NativePointer):number=> {
    let offset;
    const type = getTypeInThumb16(instruction);
    if (    type == INSTRUCTION_TYPE.B1_THUMB16 
        ||  type == INSTRUCTION_TYPE.B2_THUMB16 
        ||  type == INSTRUCTION_TYPE.BX_THUMB16 ) {

        let value;
        let idx = 0;
        if(trampoline_instructions.and(3).toUInt32()!=0){
            trampoline_instructions.writeU16(0xBF00); // nop
            idx ++ ;
        }
        if (type == INSTRUCTION_TYPE.B1_THUMB16) {
            let x = (instruction & 0xFF) << 1;
            let top_bit = x >> 8;
            let imm32 = top_bit ? (x | (0xFFFFFFFF << 8)) : x;
            value = pc.add(imm32);
            trampoline_instructions.add(idx*2).writeU16(instruction & 0xFF00); idx++;
            trampoline_instructions.add(idx*2).writeU16(0xE003              ); idx++; // B PC, #6
        }
        else if (type == INSTRUCTION_TYPE.B2_THUMB16) {
            let x = (instruction & 0x7FF) << 1;
            let top_bit = x >> 11;
            let imm32 = top_bit ? (x | (0xFFFFFFFF << 11)) : x;
            value = pc.add(imm32);
        }
        else if (type == INSTRUCTION_TYPE.BX_THUMB16) {
            value = pc;
        }
        else{
            throw new Error('unhandle case')
        }
        value =value.or(1); // thumb        
        trampoline_instructions.add(idx*2).writeU16(0xF8DF);                         idx++;
        trampoline_instructions.add(idx*2).writeU16(0xF000);                         idx++; // LDR.W PC, [PC]
        trampoline_instructions.add(idx*2).writeU16(value.and( 0xFFFF).toUInt32());  idx++;
        trampoline_instructions.add(idx*2).writeU16(value.shl(16).toUInt32());       idx++;
        offset = idx;
    }
    else if (type == INSTRUCTION_TYPE.ADD_THUMB16) {
        let r;
        let rdn = ((instruction & 0x80) >> 4) | (instruction & 0x7);
        for (r = 7; ; --r) {
            if (r != rdn) {
                break;
            }
        }
        trampoline_instructions.add(2*0).writeU16( 0xB400 | (1 << r)                ); // PUSH {Rr}
        trampoline_instructions.add(2*1).writeU16( 0x4802 | (r << 8)                ); // LDR Rr, [PC, #8]
        trampoline_instructions.add(2*2).writeU16( (instruction & 0xFF87) | (r << 3));
        trampoline_instructions.add(2*3).writeU16( 0xBC00 | (1 << r)                ); // POP {Rr}
        trampoline_instructions.add(2*4).writeU16( 0xE002                           ); // B PC, #4
        trampoline_instructions.add(2*5).writeU16( 0xBF00                           );
        trampoline_instructions.add(2*6).writePointer(pc);
        offset = 8;
    }
    else if (   type == INSTRUCTION_TYPE.MOV_THUMB16 
        ||      type == INSTRUCTION_TYPE.ADR_THUMB16 
        ||      type == INSTRUCTION_TYPE.LDR_THUMB16) {
        let r;
        let value;
        
        if (type == INSTRUCTION_TYPE.MOV_THUMB16) {
            r = instruction & 0x7;
            value = pc;
        }
        else if (type == INSTRUCTION_TYPE.ADR_THUMB16) {
            r = (instruction & 0x700) >> 8;
            value = ALIGN_PC(pc) .add( (instruction & 0xFF) << 2);
        }
        else {
            r = (instruction & 0x700) >> 8;
            value = (ALIGN_PC(pc) .add ((instruction & 0xFF) << 2)).readPointer();
        }

        trampoline_instructions.add(2*0).writeU16(0x4800 | (r << 8) ); // LDR Rd, [PC]
        trampoline_instructions.add(2*1).writeU16(0xE001            ); // B PC, #2
        trampoline_instructions.add(2*2).writePointer(value);
        offset = 4;
    }
    else if (type == INSTRUCTION_TYPE.CB_THUMB16) {

        let nonzero = (instruction & 0x800) >> 11;
        let imm32 = ((instruction & 0x200) >> 3) | ((instruction & 0xF8) >> 2);
        let value = pc.add(imm32 + 1);

        trampoline_instructions.add(2*0).writeU16(instruction & 0xFD07  );
        trampoline_instructions.add(2*1).writeU16(0xE003                );    // B PC, #6
        trampoline_instructions.add(2*2).writeU16(0xF8DF                );
        trampoline_instructions.add(2*3).writeU16(0xF000                );    // LDR.W PC, [PC]
        trampoline_instructions.add(2*4).writePointer(value);
        offset = 6;
    }
    else {
        trampoline_instructions.add(2*0).writeU16(instruction   );
        trampoline_instructions.add(2*1).writeU16(0xBF00        );  // NOP
        offset = 2;
    }
    return offset*2;
}

const relocateInstructionInThumb32 = (pc:NativePointer, high_instruction:number, low_instruction:number, trampoline_instructions:NativePointer):number=> {
    let offset;

    high_instruction    = high_instruction>>>0;
    low_instruction     = low_instruction>>>0;
                
    let instruction = (high_instruction << 16) | low_instruction;
    let type = getTypeInThumb32(instruction);
    let idx = 0;//
    // pad nop for align 4
    if(trampoline_instructions.and(3).toUInt32()!=0){
        trampoline_instructions.writeU16(0xBF00); // nop
        idx ++ ;
    }
    if (    type == INSTRUCTION_TYPE.BLX_THUMB32 
        ||  type == INSTRUCTION_TYPE.BL_THUMB32 
        ||  type == INSTRUCTION_TYPE.B1_THUMB32 
        ||  type == INSTRUCTION_TYPE.B2_THUMB32 ) {
        let value;
        let j1 = (low_instruction & 0x2000) >>> 13;
        let j2 = (low_instruction & 0x800)  >>> 11;
        let s  = (high_instruction & 0x400) >>> 10;
        let i1 = (j1^s) == 0 ? 1:0;// !(j1 ^ s) ? 1:0;
        let i2 = (j2^s) == 0 ? 1:0;// !(j2 ^ s) ? 1:0;

        if (    type == INSTRUCTION_TYPE.BLX_THUMB32 
            ||  type == INSTRUCTION_TYPE.BL_THUMB32) {
            trampoline_instructions.add(2*idx).writeU16(0xF20F); idx++;
            trampoline_instructions.add(2*idx).writeU16(0x0E09); idx++;   // ADD.W LR, PC, #9
        }
        else if (type == INSTRUCTION_TYPE.B1_THUMB32) {
            trampoline_instructions.add(2*idx).writeU16(0xD000 | ((high_instruction & 0x3C0) << 2)  ); idx++;
            trampoline_instructions.add(2*idx).writeU16(0xE003                                      ); idx++;   // B PC, #6
        }
        trampoline_instructions.add(2*idx).writeU16(0xF8DF); idx++; 
        trampoline_instructions.add(2*idx).writeU16(0xF000); idx++; // LDR.W PC, [PC]
        if (type == INSTRUCTION_TYPE.BLX_THUMB32) { 
            let x = (s << 24) | (i1 << 23) | (i2 << 22) | ((high_instruction & 0x3FF) << 12) | ((low_instruction & 0x7FE) << 1);
            let imm32 = s ? (x | (0xFFFFFFFF << 25)) : x;
            value = ALIGN_PC(pc) .add(imm32);
        }
        else if (type == INSTRUCTION_TYPE.BL_THUMB32) {
            let x = (s << 24) | (i1 << 23) | (i2 << 22) | ((high_instruction & 0x3FF) << 12) | ((low_instruction & 0x7FF) << 1);
            let imm32 = s ? (x | (0xFFFFFFFF << 25)) : x;
            value = ALIGN_PC(pc) .add( imm32 + 1);
        }
        else if (type == INSTRUCTION_TYPE.B1_THUMB32) {
            let x = (s << 20) | (j2 << 19) | (j1 << 18) | ((high_instruction & 0x3F) << 12) | ((low_instruction & 0x7FF) << 1);
            let imm32 = s ? (x | (0xFFFFFFFF << 21)) : x;
            value = ALIGN_PC(pc) .add( imm32 + 1);
        }
        else if (type == INSTRUCTION_TYPE.B2_THUMB32) {
            let x = (s << 24) | (i1 << 23) | (i2 << 22) | ((high_instruction & 0x3FF) << 12) | ((low_instruction & 0x7FF) << 1);
            let imm32 = s ? (x | (0xFFFFFFFF << 25)) : x;
            value = ALIGN_PC(pc) .add( imm32 + 1);
        }
        else{
            throw new Error(`unhandle case`)
        }
        trampoline_instructions.add(2*idx).writePointer(value); idx+=2;
        offset = idx;
    }
    else if (   type == INSTRUCTION_TYPE.ADR1_THUMB32 
            ||  type == INSTRUCTION_TYPE.ADR2_THUMB32 
            ||  type == INSTRUCTION_TYPE.LDR_THUMB32    ) {
        let value;
        let r;
        
        if (    type == INSTRUCTION_TYPE.ADR1_THUMB32 
            ||  type == INSTRUCTION_TYPE.ADR2_THUMB32   ) {
        
            r = (low_instruction & 0xF00) >> 8;
            let i = (high_instruction & 0x400) >> 10;
            let imm3 = (low_instruction & 0x7000) >> 12;
            let imm8 = instruction & 0xFF;
            let imm32 = (i << 31) | (imm3 << 30) | (imm8 << 27);
            
            if (type == INSTRUCTION_TYPE.ADR1_THUMB32) {
                value = ALIGN_PC(pc) .add(imm32);
            }
            else {
                value = ALIGN_PC(pc) .sub(imm32);
            }
        }
        else {
            let addr;
            let is_add = ((high_instruction & 0x80) >> 7)!=0;
            r = low_instruction >> 12;
            let imm32 = low_instruction & 0xFFF;
            if (is_add) {
                addr = (ALIGN_PC(pc) .add( imm32));
            }
            else {
                addr = (ALIGN_PC(pc) .sub( imm32));
            }
            value = addr.readPointer();
        }

        // LDR.W Rr, [PC, 2]
        trampoline_instructions.add(2*0).writeU16( 0xF8DF       );
        trampoline_instructions.add(2*1).writeU16( r << 12 | 4  );
        trampoline_instructions.add(2*2).writeU16( 0xBF00       );     // nop
        trampoline_instructions.add(2*3).writeU16( 0xE001       );    // B PC, #2
        trampoline_instructions.add(2*4).writePointer(value);
        offset = 6;
    }

    else if (   type == INSTRUCTION_TYPE.TBB_THUMB32 
            ||  type == INSTRUCTION_TYPE.TBH_THUMB32) {
        
        let rm = low_instruction & 0xF;
        
        let r;
        for (r = 7;; --r) {
            if (r != rm) {
                break;
            }
        }
        
        let rx;
        for (rx = 7; ; --rx) {
            if (rx != rm && rx != r) {
                break;
            }
        }
        
        trampoline_instructions.add(2*0).writeU16( 0xB400 | (1 << rx)      );    // PUSH {Rx}
        trampoline_instructions.add(2*1).writeU16( 0x4805 | (r << 8)       ); // LDR Rr, [PC, #20]
        trampoline_instructions.add(2*2).writeU16( 0x4600 | (rm << 3) | rx );   // MOV Rx, Rm
        if (type == INSTRUCTION_TYPE.TBB_THUMB32) {
            trampoline_instructions.add(2*3).writeU16(0xEB00 | r                );
            trampoline_instructions.add(2*4).writeU16(0x0000 | (rx << 8) | rx   );   // ADD.W Rx, Rr, Rx
            trampoline_instructions.add(2*5).writeU16(0x7800 | (rx << 3) | rx   );   // LDRB Rx, [Rx]
        }
        else if (type == INSTRUCTION_TYPE.TBH_THUMB32) {
            trampoline_instructions.add(2*3).writeU16(0xEB00 | r                );
            trampoline_instructions.add(2*4).writeU16(0x0040 | (rx << 8) | rx   );   // ADD.W Rx, Rr, Rx, LSL #1
            trampoline_instructions.add(2*5).writeU16(0x8800 | (rx << 3) | rx   );   // LDRH Rx, [Rx]
        }
        trampoline_instructions.add(2* 6).writeU16(0xEB00 | r              );
        trampoline_instructions.add(2* 7).writeU16(0x0040 | (r << 8) | rx  );    // ADD Rr, Rr, Rx, LSL #1
        trampoline_instructions.add(2* 8).writeU16(0x3001 | (r << 8)       ); // ADD Rr, #1
        trampoline_instructions.add(2* 9).writeU16(0xBC00 | (1 << rx)      );    // POP {Rx}
        trampoline_instructions.add(2*10).writeU16(0x4700 | (r << 3)       );    // BX Rr
        trampoline_instructions.add(2*11).writeU16(0xBF00                  );
        trampoline_instructions.add(2*12).writePointer(pc)
        offset = 14;
    }
    else {
        trampoline_instructions.add(2*0).writeU16(high_instruction  );
        trampoline_instructions.add(2*1).writeU16(low_instruction   );
        offset = 2;
    }

    return offset*2;
}


const relocateInstructionInArm = (target_addr:NativePointer, orig_instructions:NativePointer, length:number, trampoline_instructions:NativePointer)=> {

    let pc = target_addr .add( 8);
    let lr = target_addr .add(length);

    let trampoline_pos = 0;
    for (let orig_pos = 0; orig_pos < length ; orig_pos+=4) {
        let instruction = orig_instructions.add(orig_pos).readU32();
        let type = getTypeInArm(instruction);
        if (    type == INSTRUCTION_TYPE.BLX_ARM 
            ||  type == INSTRUCTION_TYPE.BL_ARM 
            ||  type == INSTRUCTION_TYPE.B_ARM 
            ||  type == INSTRUCTION_TYPE.BX_ARM ) {
            let x:number;
            let value:NativePointer;

            if (    type == INSTRUCTION_TYPE.BLX_ARM 
                ||  type == INSTRUCTION_TYPE.BL_ARM  ) {
                trampoline_instructions.add(4*trampoline_pos).writeU32(0xE28FE004); trampoline_pos++; // ADD LR, PC, #4
            }
            trampoline_instructions.add(4*trampoline_pos).writeU32(0xE51FF004); trampoline_pos++; // LDR PC, [PC, #-4]
            if (type == INSTRUCTION_TYPE.BLX_ARM) {
                x = ((instruction & 0xFFFFFF) << 2) | ((instruction & 0x1000000) >> 23);
            }
            else if (   type == INSTRUCTION_TYPE.BL_ARM 
                    ||  type == INSTRUCTION_TYPE.B_ARM   ) {
                x = (instruction & 0xFFFFFF) << 2;
            }
            else {
                x = 0;
            }
            
            let top_bit = x >> 25;
            let imm32 = top_bit ? (x | (0xFFFFFFFF << 26)) : x;
            if (type == INSTRUCTION_TYPE.BLX_ARM) {
                value = pc .add( imm32 + 1);
            }
            else {
                value = pc .add( imm32);
            }
            trampoline_instructions.add(4*trampoline_pos).writePointer(value); trampoline_pos++;
            
        }
        else if (type == INSTRUCTION_TYPE.ADD_ARM) {
            
            let rd = (instruction & 0xF000) >> 12;
            let rm = instruction & 0xF;
            
            let r;
            for (r = 12; ; --r) {
                if (r != rd && r != rm) {
                    break;
                }
            }
            
            trampoline_instructions.add(4*trampoline_pos).writeU32(0xE52D0004 | (r << 12)                   );trampoline_pos++; // PUSH {Rr}
            trampoline_instructions.add(4*trampoline_pos).writeU32(0xE59F0008 | (r << 12)                   );trampoline_pos++; // LDR Rr, [PC, #8]
            trampoline_instructions.add(4*trampoline_pos).writeU32((instruction & 0xFFF0FFFF) | (r << 16)   );trampoline_pos++;
            trampoline_instructions.add(4*trampoline_pos).writeU32(0xE49D0004 | (r << 12)                   );trampoline_pos++; // POP {Rr}
            trampoline_instructions.add(4*trampoline_pos).writeU32(0xE28FF000                               );trampoline_pos++; // ADD PC, PC
            trampoline_instructions.add(4*trampoline_pos).writePointer(pc                                   );trampoline_pos++;
        }
        else if (   type == INSTRUCTION_TYPE.ADR1_ARM 
                ||  type == INSTRUCTION_TYPE.ADR2_ARM 
                ||  type == INSTRUCTION_TYPE.LDR_ARM 
                ||  type == INSTRUCTION_TYPE.MOV_ARM  ) {

            let value:NativePointer;
            let r = (instruction & 0xF000) >>> 12;
            if (    type == INSTRUCTION_TYPE.ADR1_ARM 
                ||  type == INSTRUCTION_TYPE.ADR2_ARM 
                ||  type == INSTRUCTION_TYPE.LDR_ARM  ) {
                
                let imm32 = instruction & 0xFFF;
                if (type == INSTRUCTION_TYPE.ADR1_ARM) {
                    value = pc .add( imm32);
                }
                else if (type == INSTRUCTION_TYPE.ADR2_ARM) {
                    value = pc .sub( imm32);
                }
                else if (type == INSTRUCTION_TYPE.LDR_ARM) {
                    
                    let is_add = ((instruction & 0x800000) >> 23)!=0;
                    if (is_add) {
                        value = (pc .add( imm32)).readPointer();
                    }
                    else {
                        value = (pc .sub( imm32)).readPointer();
                    }
                }
                else{
                    throw new Error('unhandle case')
                }
            }
            else {
                value = pc;
            }
                
            trampoline_instructions.add(4*trampoline_pos).writeU32(ptr(0xE51F0000).or(r << 12).toUInt32()   ); trampoline_pos++;// LDR Rr, [PC]
            trampoline_instructions.add(4*trampoline_pos).writeU32(0xE28FF000                               ); trampoline_pos++;// ADD PC, PC
            trampoline_instructions.add(4*trampoline_pos).writePointer(value                                ); trampoline_pos++;
        }
        else {
            trampoline_instructions.add(4*trampoline_pos).writeU32(instruction); trampoline_pos++;
        }
        pc = pc.add(4);
    }
    
    return trampoline_pos*4;
}

export class ArmInlineHooker extends InlineHooker{

    private _isThumbMode():boolean {
        return this.hook_ptr.and(1).toUInt32()==1;
    }

    private _putPrecodeThumb(p:NativePointer):number {
        console.log(`prePrecode at ${p}`);
        const writer = new ThumbWriter(p);
        writer.putPushRegs([ 'r0', 'r1', 'r2', 'r3', 'r4', 'r5', 'r6', 'r7', ])
        writer.putPushRegs(['r8', 'r9', 'r10', 'r11', 'r12', 'r14'] )
        writer.putMrsRegReg('r0','apsr-nzcvq')
        writer.putPushRegs([ 'r0'])
        writer.putNop();
        writer.putMovRegReg('r1', 'sp')
        writer.putBytes([ 0x5F, 0xF8, 0x18, 0x00]) // ldr.w r0, [pc, #-0x18]
        writer.putBytes([ 0x5F, 0xF8, 0x20, 0x40]) // ldr.w r4, [pc, #-0x20]
        writer.putBlxReg('r4')
        writer.putPopRegs(['r0'])
        writer.putMsrRegReg('apsr-nzcvq','r0')
        writer.putPopRegs(['r8', 'sb', 'sl', 'fp', 'ip', 'lr'] )
        writer.putPopRegs([ 'r0', 'r1', 'r2', 'r3', 'r4', 'r5', 'r6', 'r7' ])
        writer.flush();
        let sz = writer.offset;
        return sz;
    }


    private _putPrecodeArm(p:NativePointer):number {
        console.log(`prePrecode at ${p} in Arm mode`);
        const writer = new ArmWriter(p);
        writer.putBytes([ 0xFF, 0x00, 0x2D, 0xE9 ]); // push {r0-r7};                  
        writer.putBytes([ 0x00, 0x5F, 0x2D, 0xE9 ]); // push {r8-r12, r14};
        writer.putMovRegCpsr('r0');
        writer.putBytes([ 0x04, 0x00, 0x2D, 0xE5 ]); // push {r0};
        writer.putMovRegReg('r1','sp');
        writer.putLdrRegRegOffset('r0','pc',-0x20);
        writer.putLdrRegRegOffset('r4','pc',-0x28);
        writer.putBlxReg('r4')
        writer.putBytes([ 0x04, 0x00, 0x9D, 0xE4 ]); // pop {r0};
        writer.putMovCpsrReg('r0');
        writer.putBytes([ 0x00, 0x5f, 0xBD, 0xE8 ]); // pop {r8-r12, r14};
        writer.putBytes([ 0xFF, 0x00, 0xBD, 0xE8 ]); // pop {r0-r7};
        writer.flush();
        let sz = writer.offset;
        return sz;
    }

    putPrecode(p:NativePointer):[number, NativePointer] {
        let offset=0;
        // write hook_fun_ptr
        p.add(offset).writePointer(this.hook_fun_ptr); offset += Process.pointerSize;
        // write arg1
        p.add(offset).writePointer(this.para1); offset += Process.pointerSize;
        // write precode
        let trampolineCodeAddr = p.add(offset);
        offset += this._isThumbMode()   ? this._putPrecodeThumb(trampolineCodeAddr) 
                                        : this._putPrecodeArm(trampolineCodeAddr);
        return [offset, trampolineCodeAddr]
    }

    relocCode(from:NativePointer, to:NativePointer, sz:number):[number, ArrayBuffer] {
        // fix address
        let offset = 0;
        let woffset = 0;
        while(offset<sz){
            let inst = Instruction.parse(from.add(offset)) as ArmInstruction;
            let pc = from.add(offset).and(~1);
            //let instbs = readMemoryArrayBuffer(from, offset);
            //if(inst.size==4 && inst.mnemonic =='bl' && inst.operands[0].type=='imm') {
            //    // handle bl, imm thumb32 
            //    const writer = new ThumbWriter(to.add(woffset));
            //    if(to.add(woffset).and(3).toUInt32()!=0){ writer.putNop(); }
            //    writer.putBytes([0x0F, 0xF2, 0x09, 0x0E]);    // lr, pc, #9
            //    writer.putLdrRegRegOffset('pc','pc',0); //ldr.w   pc, [pc, #0]
            //    woffset+= writer.offset;
            //    let value = ptr(inst.operands[0].value).or(1)
            //    to.add(woffset).writePointer(value);
            //    woffset += 4;
            //}
            //else 
            if(!this._isThumbMode()) { // arm
                woffset += relocateInstructionInArm(pc, pc, 4, to.add(woffset));
            }
            else if(inst.size==2) { // thumb16
                woffset += relocateInstructionInThumb16(pc.add(4), pc.readU16(), to.add(woffset));
            }
            else if(inst.size==4) { // thumb32
                woffset += relocateInstructionInThumb32(pc.add(4), pc.readU16(), pc.add(2).readU16(), to.add(woffset));
            }
            else{
                throw new Error(`unhandle case when relocate thumb code`)
            }
            offset += inst.size;
        }
        let orig_bytes = readArrayBufferFromMemory(from,offset);
        return [woffset, orig_bytes]
    }

    canBranchDirectlyBetween(from:NativePointer, to:NativePointer):boolean {
        let distance = to.or(1).sub(from.or(1)).toInt32();
        return distance >=-8388608 && distance<= 8388607;
    }

    getJumpInstLen(from:NativePointer, to:NativePointer):number{
        if(this.canBranchDirectlyBetween(from, to)) return 4;
        else return 8;
    }

    putJumpCode(from:NativePointer, to:NativePointer):number {
        if(this._isThumbMode()){
            let code = from.and(~1);
            const writer = new ThumbWriter(code);
            if(this.canBranchDirectlyBetween(from,to)){
                writer.putBImm(to.or(1))
                writer.flush();
                return writer.offset;
            }
            else{
                if(code.and(0x3).equals(0)) {
                    writer.putLdrRegRegOffset('pc','pc',0)
                }
                else{
                    writer.putLdrRegRegOffset('pc','pc',2)
                }
                writer.flush()
                code.add(writer.offset).writePointer(to.or(1))
                return writer.offset+Process.pointerSize;
            }
        }
        else {
            let code = from;
            const writer = new ArmWriter(code);
            if(this.canBranchDirectlyBetween(from, to)){
                writer.putBImm(to);
                writer.flush();
                return writer.offset;
            }
            else{
                writer.putLdrRegRegOffset('pc','pc',-4);
                writer.flush();
                from.add(writer.offset).writePointer(to)
                return writer.offset+Process.pointerSize;
            }
        }
    }
}

export let getRegs = (sp:NativePointer) =>{
    return  {
        r0      : sp.add(Process.pointerSize*7 ).readPointer(),
        r1      : sp.add(Process.pointerSize*8 ).readPointer(),
        r2      : sp.add(Process.pointerSize*9 ).readPointer(),
        r3      : sp.add(Process.pointerSize*10).readPointer(),
        r4      : sp.add(Process.pointerSize*11).readPointer(),
        r5      : sp.add(Process.pointerSize*12).readPointer(),
        r6      : sp.add(Process.pointerSize*13).readPointer(),
        r7      : sp.add(Process.pointerSize*14).readPointer(),
        r8      : sp.add(Process.pointerSize*1 ).readPointer(),
        r9      : sp.add(Process.pointerSize*2 ).readPointer(),
        r10     : sp.add(Process.pointerSize*3 ).readPointer(),
        r11     : sp.add(Process.pointerSize*4 ).readPointer(),
        r12     : sp.add(Process.pointerSize*5 ).readPointer(),
        r14     : sp.add(Process.pointerSize*6 ).readPointer(),
        apsr    : sp.add(Process.pointerSize*0 ).readPointer(),
    };
}
