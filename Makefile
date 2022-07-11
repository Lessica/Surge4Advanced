TARGET := iphone:clang:14.5:13.0
INSTALL_TARGET_PROCESSES = Surge-iOS Surge-iOS-NE Surge-Enterprise Surge-Enterprise-NE

include $(THEOS)/makefiles/common.mk

TWEAK_NAME = Surge4Advanced

Surge4Advanced_FILES = Tweak.x
Surge4Advanced_CFLAGS = -fobjc-arc
Surge4Advanced_FRAMEWORKS = UIKit

include $(THEOS_MAKE_PATH)/tweak.mk
