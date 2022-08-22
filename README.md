# Frida inlinehook

## This project is intended to implment inlinehook with Frida on multiple architecture, Arm/Thumb, Arm64, X86 and X64.

## How to build
```bash
git clone https://github.com/mengxipeng1122/Frida-Inlinehook
export NDKPATH= <path to your own NDK>;
pip install Jinja2  frida lief
cd Frida-Inlinehook
mkdir soinfos
make
```

## How to test
```
# the following 3 tests need to connect to an Android device with started Frida server.
make run_arm ;  # test arm architecure
make run_arm64 ;  # test arm64 architecure
make run_thumb ;  # test thumb architecure
# the flollowing 2 tests need to run on a Linux PC.
make run_x64 ;  # test x64 architecure
make run_x86 ;  # test x64 architecure
```

# Under the hood
I write a simple program for test, it's source code is [here](https://github.com/mengxipeng1122/Frida-Inlinehook/blob/master/jni/testexe.cpp).

## interface 
```typescript
export const inlineHookPatch = (
    hook_ptr:NativePointer,            // pointer to the hook
    hook_fun_ptr:NativePointer,        // the function will be invoked once program hit hook point. 
    para1:NativePointer,               // a pointer , this parameter will be pass to hook_fun as the 1st parameter.
    trampoline_ptr?:NativePointer,     // optional, pointer to put trampoline code, and function will alloc buff automatically when callers don't provide this parameter.
):number ;    // return length of trampoline code 
```

[test.ts](https://github.com/mengxipeng1122/Frida-Inlinehook/blob/master/index.ts) shows how to use this function.
