BPF_CLANG ?= clang
BPF_CFLAGS := -O2 -g -Wall -Werror -target bpf

all: guard.bpf.o

guard.bpf.o: guard.bpf.c vmlinux.h
	$(BPF_CLANG) $(BPF_CFLAGS) -c guard.bpf.c -o guard.bpf.o

clean:
	rm -f guard.bpf.o
