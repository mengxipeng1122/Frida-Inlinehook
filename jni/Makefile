

NDKPATH=/mnt/axly/hackings/android-utils/android-ndk-r15c/

all:exe_x86 exe_x64
	${NDKPATH}/ndk-build V=1
	adb push ../libs/armeabi-v7a/exe_* /data/local/tmp;  
	adb push ../libs/arm64-v8a/exe_* /data/local/tmp;  

clean:
	${NDKPATH}/ndk-build clean


exe_x86:testexe.cpp
	$(CC) -o $@ $^ $(LDFLAGS) $(CXXFLAGS) -m32 

exe_x64:testexe.cpp
	$(CC) -o $@ $^ $(LDFLAGS) $(CXXFLAGS) 

