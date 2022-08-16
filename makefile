

build:
	(cd jni ; make)
	./utils/so2tsmodule.py --no-content libs/arm64-v8a/exe_arm64 -o ./soinfos/exe_arm64.ts
	./utils/so2tsmodule.py --no-content libs/armeabi-v7a/exe_arm -o ./soinfos/exe_arm.ts
	./utils/so2tsmodule.py --no-content libs/armeabi-v7a/exe_thumb -o ./soinfos/exe_thumb.ts
	./utils/so2tsmodule.py --no-content jni/exe_x86 -o ./soinfos/exe_x86.ts
	./utils/so2tsmodule.py --no-content jni/exe_x64 -o ./soinfos/exe_x64.ts
	npm run build

kill:
	-killall -9 exe_x86
	-killall -9 exe_x64
	-adb shell killall -9 exe_arm64
	-adb shell killall -9 exe_arm
	-adb shell killall -9 exe_thumb

run_arm64:
	-adb shell killall -9 exe_arm64
	./utils/runfrida.py -p /data/local/tmp/exe_arm64 -l _agent.js  -r

run_arm:
	-adb shell killall -9 exe_arm
	./utils/runfrida.py -p /data/local/tmp/exe_arm -l _agent.js  -r

run_thumb:
	-adb shell killall -9 exe_thumb
	./utils/runfrida.py -p /data/local/tmp/exe_thumb -l _agent.js  -r

run_x86:
	-killall -9 exe_x86
	frida -f ./jni/exe_x86 -l _agent.js  --no-pause -o /tmp/log.txt

run_x64:
	-killall -9 exe_x64
	frida -f ./jni/exe_x64 -l _agent.js  --no-pause -o /tmp/log.txt

