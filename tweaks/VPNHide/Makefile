TARGET := iphone:clang:latest:14.0
ARCHS = arm64
THEOS_PACKAGE_SCHEME = rootless
THEOS_DEVICE_IP = 192.168.1.148
INSTALL_TARGET_PROCESSES = MtsServiceRu

include $(THEOS)/makefiles/common.mk

TWEAK_NAME = VPNHide

$(TWEAK_NAME)_FILES = Tweak.mm fishhook/fishhook.c
$(TWEAK_NAME)_CFLAGS = -fobjc-arc
$(TWEAK_NAME)_CCFLAGS = -fobjc-arc

include $(THEOS_MAKE_PATH)/tweak.mk
