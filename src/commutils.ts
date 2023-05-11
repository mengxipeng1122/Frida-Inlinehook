
export const readArrayBufferFromMemory=(p:NativePointer, sz?:number):ArrayBuffer=>{
    if(sz==undefined) sz = 0x10;
    let ab = p.readByteArray(sz);
    if(ab==null) throw new Error(`read ${sz} bytes from ${p} failed`)
    return ab;
}