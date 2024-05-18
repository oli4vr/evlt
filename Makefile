# Variables
NUM_CPUS := $(shell nproc)
NUM_CTHR := $(shell echo $$(($(NUM_CPUS) * 2)))
MAINDIR := $(CURDIR)
INSTALL_DIR := $(MAINDIR)/inst
LIBSSH_DIR := $(MAINDIR)/libssh
OPENSSL_REPO := https://github.com/openssl/openssl.git
LIBSSH_REPO := https://git.libssh.org/projects/libssh.git
CFLAGS := -Wl -Bstatic -O3 -I$(LIBSSH_DIR)/build/include -I$(LIBSSH_DIR)/include -I$(INSTALL_DIR)/include -I$(MAINDIR)/openssl/include
LDFLAGS := -L. -L$(INSTALL_DIR)/lib -L$(INSTALL_DIR)/lib64 -lssh -lssl -lcrypto -lpthread
JOBS := -j$(NUM_CTHR)

# Build all
all: ssl ssh main

# Build openssl as a static library
ssl:
	rm -rf $(INSTALL_DIR) 2>/dev/null
	git clone $(OPENSSL_REPO) openssl
	cd openssl && ./config --prefix=$(INSTALL_DIR) no-shared no-docs && make $(JOBS) && make install

# Build libssh and make it static
ssh:
	rm -rf $(LIBSSH_DIR)
	git clone $(LIBSSH_REPO) $(LIBSSH_DIR)
	mkdir -p $(LIBSSH_DIR)/build
	cd $(LIBSSH_DIR)/build && cmake -DCMAKE_INSTALL_PREFIX=$(INSTALL_DIR) -DWITH_EXAMPLES=OFF -DBUILD_SHARED_LIBS=OFF -DLIBSSH_STATIC=ON -DWITH_ZLIB=OFF -DOPENSSL_ROOT_DIR=$(INSTALL_DIR) -DOPENSSL_LIBRARIES="$(INSTALL_DIR)/lib64/libssl.a;$(INSTALL_DIR)/lib64/libcrypto.a;$(INSTALL_DIR)/lib64" .. && make $(JOBS) && make install

# Build the main application
main:
	gcc -c encrypt.c -o encrypt.o $(CFLAGS)
	gcc -c hexenc.c -o hexenc.o $(CFLAGS)
	gcc -c pipes.c -o pipes.o $(CFLAGS)
	gcc -c evlt.c -o evlt.o $(CFLAGS)
	gcc -c sftp.c -o sftp.o $(CFLAGS) 
	gcc -static-libgcc main.c -o evlt encrypt.o hexenc.o pipes.o sftp.o evlt.o $(CFLAGS) $(LDFLAGS) 

# Clean only the main application
clean:
	rm -rf *.o evlt sftp libsftp.a

# Clean everything including dependant libraries
superclean:
	rm -rf inst openssl libssh evlt *.o *.a

# Install to ~/bin
install:
	echo mkdir -p ~/bin | /bin/bash 2>/dev/null
	cp evlt ~/bin/

# Uninstall
uninstall:
	rm ~/bin/evlt
