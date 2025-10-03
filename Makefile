# Variables
NUM_CPUS := $(shell nproc)
NUM_CTHR := $(shell echo $$(($(NUM_CPUS) * 4)))
MAINDIR := $(CURDIR)
INSTALL_DIR := $(MAINDIR)/inst
LIBSSH_DIR := $(MAINDIR)/libssh
QRENC_DIR := $(MAINDIR)/qrenc
OPENSSL_REPO := https://github.com/openssl/openssl.git
QRENC_REPO := https://github.com/fukuchi/libqrencode.git
LIBSSH_PKG := https://www.libssh.org/files/0.11/libssh-0.11.3.tar.xz
CFLAGS := -O3 -I$(LIBSSH_DIR)/build/include -I$(LIBSSH_DIR)/include -I$(INSTALL_DIR)/include -I$(MAINDIR)/openssl/include
LDFLAGS := -L$(INSTALL_DIR)/lib -L$(INSTALL_DIR)/lib64 -lpthread
STATIC_LIBS := $(INSTALL_DIR)/lib/libssh.a $(INSTALL_DIR)/lib64/libssl.a $(INSTALL_DIR)/lib64/libcrypto.a $(QRENC_DIR)/build/libqrencode.a
JOBS := -j$(NUM_CTHR)

# Build all
all: ssl ssh qrenc main pkg

# Build openssl as a static library
ssl:
	rm -rf $(INSTALL_DIR) 2>/dev/null
	git clone $(OPENSSL_REPO) openssl
	cd openssl && ./config --prefix=$(INSTALL_DIR) no-shared no-docs && make $(JOBS) && make install

# Build libssh and make it static
ssh:
	rm -rf $(LIBSSH_DIR) 2>/dev/null
	wget --no-check-certificate $(LIBSSH_PKG)
	xz -cd libssh-*.tar.xz | tar -xvf -
	rm -rf libssh-*.tar.xz
	mv libssh-* libssh
	mkdir -p $(LIBSSH_DIR)/build
	cd $(LIBSSH_DIR)/build && cmake -DWITH_NACL=OFF -DWITH_GSSAPI=OFF -DCMAKE_INSTALL_PREFIX=$(INSTALL_DIR) -DWITH_EXAMPLES=OFF -DBUILD_SHARED_LIBS=OFF -DLIBSSH_STATIC=ON -DWITH_ZLIB=OFF -DOPENSSL_ROOT_DIR=$(INSTALL_DIR) -DOPENSSL_LIBRARIES="$(INSTALL_DIR)/lib64/libssl.a;$(INSTALL_DIR)/lib64/libcrypto.a;$(INSTALL_DIR)/lib64" .. && make $(JOBS) && make install

# Build qrencode library as a static library
qrenc:
	rm -rf $(QRENC_DIR) 2>/dev/null
	git clone $(QRENC_REPO) $(QRENC_DIR)
	cmake -B $(QRENC_DIR)/build -DWITHOUT_PNG=ON -DWITH_TESTS=OFF -DWITH_TOOLS=OFF -DBUILD_SHARED_LIBS=OFF -DZLIB_INCLUDE_DIR= -DICONV_INCLUDE_DIR= $(QRENC_DIR)
	make -C $(QRENC_DIR)/build

# Build the main application
main:
	gcc -c encrypt.c -o encrypt.o $(CFLAGS)
	gcc -c hexenc.c -o hexenc.o $(CFLAGS)
	gcc -c pipes.c -o pipes.o $(CFLAGS)
	gcc -c evlt.c -o evlt.o $(CFLAGS)
	gcc -c sftp.c -o sftp.o $(CFLAGS) 
	gcc -c inifind.c -o inifind.o $(CFLAGS) 
	gcc -c qr.c -o qr.o $(CFLAGS) 
	gcc main.c -o evlt encrypt.o hexenc.o pipes.o sftp.o evlt.o inifind.o qr.o $(STATIC_LIBS) $(CFLAGS) $(LDFLAGS)

# Clean only the main application
clean:
	rm -rf *.o evlt sftp libsftp.a *.rpm *.deb

# Clean everything including dependant libraries
superclean: clean
	rm -rf inst openssl libssh evlt *.o *.a localvaults qrenc

# Install to ~/bin
install:
	echo mkdir -p ~/bin | /bin/bash 2>/dev/null
	cp evlt ~/bin/

# Uninstall
uninstall:
	rm ~/bin/evlt

# Packages
pkg:
	./buildpkg.sh
