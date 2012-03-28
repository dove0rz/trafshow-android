LOCAL_PATH := $(call my-dir)
include $(CLEAR_VARS)

LOCAL_CFLAGS:=-O2 -g -DHAVE_CONFIG_H 
LOCAL_C_INCLUDES += \
	external/libpcap \
	external/libncurses/include

LOCAL_MODULE:= trafshow
LOCAL_MODULE_TAGS:= eng
#LOCAL_SYSTEM_SHARED_LIBRARIES := libc
LOCAL_LDLIBS += -lpthread -lm
LOCAL_SHARED_LIBRARIES := libncurses 
LOCAL_STATIC_LIBRARIES += libpcap
#LOCAL_PRELINK_MODULE := false


LOCAL_SRC_FILES:= \
	trafshow.c screen.c colormask.c getkey.c selector.c \
	events.c session.c show_if.c show_stat.c show_dump.c \
	parse_dl.c parse_ip.c netstat.c cisco_netflow.c addrtoname.c \
	hashtab.c lookupa.c recycle.c util.c help_page.c domain_resolver.c \
	dn_comp.c


include $(BUILD_EXECUTABLE)



