WFLAGS ?= -Wall -Wextra -Wmissing-prototypes -Wdiv-by-zero -Wbad-function-cast \
	-Wcast-align -Wcast-qual -Wfloat-equal -Wmissing-declarations -Wnested-externs \
	-Wno-unknown-pragmas -Wpointer-arith -Wredundant-decls -Wstrict-prototypes \
	-Wswitch-enum -Wno-type-limits
CFLAGS ?= -O3 -march=native -fno-exceptions -flto $(WFLAGS)
CFLAGS += -I. -Ilibhydrogen
OBJ = libhydrogen/hydrogen.o src/hsign.o src/base64.o
STRIP ?= strip

SRC = \
	libhydrogen/hydrogen.c \
	src/base64.c \
	src/hsign.c

libhydrogen/hydrogen.c:
	git submodule update --init || echo "** Make sure you cloned the repository **" >&2

all: bin

bin: hsign

$(OBJ): $(SRC)

.c.o:
	$(CC) $(CFLAGS) -o $@ -c $<

hsign: $(OBJ)
	$(CC) $(CFLAGS) -o hsign $(OBJ)

.PHONY: clean

clean:
	rm -f hsign $(OBJ)

.SUFFIXES: .c .o
