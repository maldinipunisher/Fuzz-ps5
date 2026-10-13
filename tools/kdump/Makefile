# PS5 Kernel Dumper
# Requires: ps5-payload-dev SDK (https://github.com/ps5-payload-dev/sdk)

PS5_HOST ?= ps5
PS5_PORT ?= 9021
PS5_PAYLOAD_SDK ?= /Users/macbookairm1/Data/Hypervisor-ps5/ps5sdk

ifdef PS5_PAYLOAD_SDK
    include $(PS5_PAYLOAD_SDK)/toolchain/prospero.mk
else
    $(error PS5_PAYLOAD_SDK is undefined)
endif

ELF := kdump.elf

CFLAGS := -Wall -g

all: $(ELF)

$(ELF): kdump.c
	$(CC) $(CFLAGS) -o $@ $^

clean:
	rm -f $(ELF)

send: $(ELF)
	$(PS5_DEPLOY) -h $(PS5_HOST) -p $(PS5_PORT) $^
