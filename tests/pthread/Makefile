APPLICATION = pthread
include ../Makefile.tests_common

BOARD_BLACKLIST := arduino-mega2560 waspmote-pro
# arduino-mega2560: unknown type name: clockid_t

USEMODULE += posix
USEMODULE += pthread

include $(RIOTBASE)/Makefile.include
