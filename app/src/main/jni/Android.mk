LOCAL_PATH := $(call my-dir)
 
include $(CLEAR_VARS)
LOCAL_MODULE:= substrate-dvm
LOCAL_SRC_FILES := libsubstrate-dvm.so
include $(PREBUILT_SHARED_LIBRARY)

include $(CLEAR_VARS)
LOCAL_MODULE:= substrate
LOCAL_SRC_FILES := libsubstrate.so
include $(PREBUILT_SHARED_LIBRARY)

include $(CLEAR_VARS)
LOCAL_MODULE := TKHooklib
LOCAL_SRC_FILES := libTKHooklib.so
include $(PREBUILT_SHARED_LIBRARY)


include $(CLEAR_VARS)
LOCAL_MODULE    := cydiasubstrate_nativehooktools.cy
LOCAL_SRC_FILES := cydiasubstrate_nativehooktools.cpp
#LOCAL_SHARED_LIBRARIES := substrate-dvm substrate
LOCAL_LDLIBS:= -L$(LOCAL_PATH) -lsubstrate -lsubstrate-dvm -llog 
LOCAL_SHARED_LIBRARIES := \
	libdl 
LOCAL_CFLAGS += -Wpointer-arith -fpermissive -Wformat
#LOCAL_CFLAGS += -fvisibility=hidden -fno-inline -fomit-frame-pointer -fno-stack-protector -O2 -Os -Wpointer-arith -std=c++11 -fpermissive
include $(BUILD_SHARED_LIBRARY)