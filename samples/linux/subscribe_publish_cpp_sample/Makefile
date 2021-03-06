#This target is to ensure accidental execution of Makefile as a bash script will not execute commands like rm in unexpected directories and exit gracefully.
.prevent_execution:
	exit 0

CC = g++

#remove @ for no make command prints
DEBUG = @

APP_DIR = .
APP_INCLUDE_DIRS += -I $(APP_DIR)
APP_NAME = subscribe_publish_cpp_sample
APP_SRC_FILES = $(APP_NAME).cpp

#IoT client directory
IOT_CLIENT_DIR = ../../..

USE_WOLFSSL ?= 1

ifeq ($(USE_WOLFSSL), 1))
	PLATFORM_DIR = $(IOT_CLIENT_DIR)/platform/linux/wolfssl
else
	PLATFORM_DIR = $(IOT_CLIENT_DIR)/platform/linux/mbedtls
endif

PLATFORM_COMMON_DIR = $(IOT_CLIENT_DIR)/platform/linux/common

IOT_INCLUDE_DIRS += -I $(IOT_CLIENT_DIR)/include
IOT_INCLUDE_DIRS += -I $(IOT_CLIENT_DIR)/external_libs/jsmn
IOT_INCLUDE_DIRS += -I $(PLATFORM_COMMON_DIR)
IOT_INCLUDE_DIRS += -I $(PLATFORM_DIR)

IOT_SRC_FILES += $(shell find $(IOT_CLIENT_DIR)/src/ -name '*.c')
IOT_SRC_FILES += $(shell find $(IOT_CLIENT_DIR)/external_libs/jsmn -name '*.c')
IOT_SRC_FILES += $(shell find $(PLATFORM_DIR)/ -name '*.c')
IOT_SRC_FILES += $(shell find $(PLATFORM_COMMON_DIR)/ -name '*.c')

#TLS

MBEDTLS_DIR = $(IOT_CLIENT_DIR)/external_libs/mbedTLS
WOLFSSL_DIR = $(IOT_CLIENT_DIR)/external_libs/wolfssl

ifeq ($(USE_WOLFSSL), 1)
	TLSDIR = $(WOLFSSL_DIR)
	COMPILER_FLAGS += -DUSE_WOLFSSL
	TLS_LIB_DIR = $(WOLFSSL_DIR)/src/.libs
	TLS_INCLUDE_DIR = -I $(WOLFSSL_DIR)/wolfssl -I $(WOLFSSL_DIR)
	EXTERNAL_LIBS += -L$(WOLFSSL_DIR)
	LD_FLAG += -Wl,-rpath,$(TLS_LIB_DIR)
	LD_FLAG += -ldl $(TLS_LIB_DIR)/libwolfssl.so -lpthread
else
	TLSDIR = $(MBEDTLS_DIR)
	COMPILER_FLAGS += -DUSE_MBEDTLS
	TLS_LIB_DIR = $(MBEDTLS_DIR)/library
	TLS_INCLUDE_DIR = -I $(MBEDTLS_DIR)/include
	EXTERNAL_LIBS += -L$(TLS_LIB_DIR)
	LD_FLAG += -Wl,-rpath,$(TLS_LIB_DIR)
	LD_FLAG += -ldl $(TLS_LIB_DIR)/libmbedtls.a $(TLS_LIB_DIR)/libmbedcrypto.a $(TLS_LIB_DIR)/libmbedx509.a -lpthread
endif

#Aggregate all include and src directories
INCLUDE_ALL_DIRS += $(IOT_INCLUDE_DIRS)
INCLUDE_ALL_DIRS += $(TLS_INCLUDE_DIR)
INCLUDE_ALL_DIRS += $(APP_INCLUDE_DIRS)

SRC_FILES += $(APP_SRC_FILES)
SRC_FILES += $(IOT_SRC_FILES)

# Logging level control
LOG_FLAGS += -DENABLE_IOT_DEBUG
LOG_FLAGS += -DENABLE_IOT_INFO
LOG_FLAGS += -DENABLE_IOT_WARN
LOG_FLAGS += -DENABLE_IOT_ERROR

COMPILER_FLAGS += $(LOG_FLAGS)
#If the processor is big endian uncomment the compiler flag
#COMPILER_FLAGS += -DREVERSED
COMPILER_FLAGS += -std=c++0x

TLS_MAKE_CMD = $(MAKE) -C $(TLSDIR)

PRE_MAKE_CMD = $(TLS_MAKE_CMD)
MAKE_CMD = $(CC) $(SRC_FILES) $(COMPILER_FLAGS) -o $(APP_NAME) $(LD_FLAG) $(EXTERNAL_LIBS) $(INCLUDE_ALL_DIRS)

all:
	$(PRE_MAKE_CMD)
	$(DEBUG)$(MAKE_CMD)
	$(POST_MAKE_CMD)

clean:
	rm -f $(APP_DIR)/$(APP_NAME)
	$(MBED_TLS_MAKE_CMD) clean
