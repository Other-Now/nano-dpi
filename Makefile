CC      ?= gcc
CFLAGS  ?= -O2 -g
CFLAGS  += -std=c11 -D_DEFAULT_SOURCE -Wall -Wextra -Wshadow -Iinclude
LDLIBS  += -lcrypto -lm

SRC  := src/pcapio.c src/pkt.c src/reasm.c src/flow.c src/dpi.c src/quic.c \
        src/apps.c src/rules.c src/policer.c src/engine.c
OBJ  := $(SRC:src/%.c=build/%.o)

all: build/nanodpi build/test_nanodpi build/bench_rules build/bench_policer

build/%.o: src/%.c include/*.h | build
	$(CC) $(CFLAGS) -c $< -o $@

build/nanodpi: tools/nanodpi.c $(OBJ)
	$(CC) $(CFLAGS) $^ -o $@ $(LDLIBS)

build/test_nanodpi: tests/test_nanodpi.c $(OBJ)
	$(CC) $(CFLAGS) $^ -o $@ $(LDLIBS)

build/bench_rules: bench/bench_rules.c $(OBJ)
	$(CC) $(CFLAGS) $^ -o $@ $(LDLIBS)

build/bench_policer: bench/bench_policer.c $(OBJ)
	$(CC) $(CFLAGS) $^ -o $@ $(LDLIBS)

build:
	mkdir -p build

test: build/test_nanodpi
	./build/test_nanodpi

# AddressSanitizer + UBSan build of everything, in its own directory
asan:
	$(MAKE) BUILD=asan CFLAGS="-O1 -g -fsanitize=address,undefined -fno-omit-frame-pointer" \
	        LDFLAGS="-fsanitize=address,undefined" all-asan

all-asan:
	mkdir -p build-asan
	$(CC) $(CFLAGS) -std=c11 -D_DEFAULT_SOURCE -Iinclude tools/nanodpi.c $(SRC) -o build-asan/nanodpi $(LDLIBS)
	$(CC) $(CFLAGS) -std=c11 -D_DEFAULT_SOURCE -Iinclude tests/test_nanodpi.c $(SRC) -o build-asan/test_nanodpi $(LDLIBS)

# libFuzzer target (needs clang)
FUZZ_CC ?= clang
fuzz:
	mkdir -p build-fuzz
	$(FUZZ_CC) -O1 -g -fsanitize=fuzzer,address,undefined -std=c11 -D_DEFAULT_SOURCE -Iinclude \
	      fuzz/fuzz_engine.c $(SRC) -o build-fuzz/fuzz_engine $(LDLIBS)

clean:
	rm -rf build build-asan build-fuzz

.PHONY: all test asan all-asan fuzz clean
