PS5_HOST ?= ps5
PS5_PORT ?= 9021

ifdef PS5_PAYLOAD_SDK
    include $(PS5_PAYLOAD_SDK)/toolchain/prospero.mk
else
    $(error PS5_PAYLOAD_SDK is undefined)
endif

CFLAGS := -Wall -O2

all: sony_syscall_fuzzer.elf ioctl_fuzzer.elf target55.elf target55_v2.elf target55_v3.elf target55_v4.elf sony_fuzz_safe.elf target421.elf crash_deep.elf

sony_syscall_fuzzer.elf: sony_syscall_fuzzer.c
	$(CC) $(CFLAGS) -o $@ $^

ioctl_fuzzer.elf: ioctl_fuzzer.c
	$(CC) $(CFLAGS) -o $@ $^

target55.elf: target55.c
	$(CC) $(CFLAGS) -o $@ $^

target55_v2.elf: target55_v2.c
	$(CC) $(CFLAGS) -o $@ $^

target55_v3.elf: target55_v3.c
	$(CC) $(CFLAGS) -o $@ $^

target55_v4.elf: target55_v4.c
	$(CC) $(CFLAGS) -o $@ $^

sony_fuzz_safe.elf: sony_fuzz_safe.c
	$(CC) $(CFLAGS) -DSKIP_COUNT=$(SKIP) -o $@ $^

target421.elf: target421.c
	$(CC) $(CFLAGS) -o $@ $^

crash_deep.elf: crash_deep.c
	$(CC) $(CFLAGS) -DTARGET_IDX=$(CIDX) -o $@ $^

target622.elf: target622.c
	$(CC) $(CFLAGS) -o $@ $^

clean:
	rm -f *.elf

test-syscall: sony_syscall_fuzzer.elf
	$(PS5_DEPLOY) -h $(PS5_HOST) -p $(PS5_PORT) $<

test-ioctl: ioctl_fuzzer.elf
	$(PS5_DEPLOY) -h $(PS5_HOST) -p $(PS5_PORT) $<
