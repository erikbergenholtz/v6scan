CC=gcc
CFLAGS=-Wall -Werror -c
CINCLUDE=-I./include
LDFLAGS=-lpcap -lpthread

SRCDIR=src
BUILD=build
SIMDIR=simulation
SIMS=$(wildcard $(SIMDIR)/*.c)
SIMO=$(patsubst $(SIMDIR)/*.c,%.run,$(SIMS))
SRC=$(wildcard $(SRCDIR)/*.c)
OBJ=$(patsubst $(SRCDIR)/%.c,$(BUILD)/%.o,$(SRC))


all: v6scan simulation

v6scan: $(OBJ)
	@mkdir -p $(BUILD)
	$(CC) $^ -o$@ $(LDFLAGS)

$(BUILD)/%.o: $(SRCDIR)/%.c
	@mkdir -p $(BUILD)
	$(CC) $^ -o$@ $(CFLAGS) $(CINCLUDE)

simulation: dehcpsim

dehcpsim: $(SIMDIR)/dehcpsim.c
	$(CC) -std=c99 $^ -o$@
clean:
	rm -rf $(BUILD) v6scan dehcpsim *.csv
	sudo rm -rf dump*

.PHONY: all clean simulation
