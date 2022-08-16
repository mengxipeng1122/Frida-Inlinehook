

NDKPATH=/mnt/axly/hackings/android-utils/android-ndk-r15c/

all:exe_x86 exe_x64
	${NDKPATH}/ndk-build V=1
	adb push ../libs/armeabi-v7a/exe_* /data/local/tmp;  
	adb push ../libs/arm64-v8a/exe_* /data/local/tmp;  
	cp ../libs/arm64-v8a/exe_arm64 /tmp/exe_arm64.elf
	cp ../libs/armeabi-v7a/exe_arm /tmp/exe_arm.elf
	cp ../libs/armeabi-v7a/exe_thumb /tmp/exe_thumb.elf
	cp ./exe_x86 /tmp/exe_x86.elf
	cp ./exe_x64 /tmp/exe_x64.elf

clean:
	${NDKPATH}/ndk-build clean


exe_x86:testexe.cpp
	$(CC) -o $@ $^ $(LDFLAGS) $(CXXFLAGS) -m32 

exe_x64:testexe.cpp
	$(CC) -o $@ $^ $(LDFLAGS) $(CXXFLAGS) 

