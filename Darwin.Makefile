OUTPUTDIR=macos-build-outputdir
INSTALL_PREFIX=$(shell pwd)/$(OUTPUTDIR)
PKG_CONFIG_PATH=/usr/local/opt/openssl@3/lib/pkgconfig

DB4_VERSION=4.8.30
PLOG_VERSION=1.1.9
BHD_VDF_VERSION=0.0.57
BLS_SIGNATURES_VERSION=1.0.7
BDB_PREFIX="$(INSTALL_PREFIX)/db4"

all: Makefile

clean:
	rm -rf ./configure Makefile $(INSTALL_PREFIX)

configure:
	./autogen.sh

outputdir:
	mkdir -p $(INSTALL_PREFIX)

Makefile: outputdir configure $(INSTALL_PREFIX)/db-$(DB4_VERSION).NC.tar.gz $(INSTALL_PREFIX)/$(PLOG_VERSION).tar.gz $(INSTALL_PREFIX)/v$(BHD_VDF_VERSION).tar.gz $(INSTALL_PREFIX)/$(BLS_SIGNATURES_VERSION).tar.gz
	./configure LDFLAGS="-L${INSTALL_PREFIX}/lib" CXXFLAGS="-I${INSTALL_PREFIX}/include" BDB_LIBS="-L${BDB_PREFIX}/lib -ldb_cxx-4.8" BDB_CFLAGS="-I${BDB_PREFIX}/include" --enable-debug

$(INSTALL_PREFIX)/db-$(DB4_VERSION).NC.tar.gz:
	cd $(INSTALL_PREFIX) && CFLAGS="-Wno-error=implicit-function-declaration" ../contrib/install_db4.sh .

$(INSTALL_PREFIX)/$(PLOG_VERSION).tar.gz:
	cd $(INSTALL_PREFIX) && wget https://github.com/SergiusTheBest/plog/archive/refs/tags/$(PLOG_VERSION).tar.gz && tar xf $(PLOG_VERSION).tar.gz && cd plog-$(PLOG_VERSION) && cmake . -DCMAKE_INSTALL_PREFIX=$(INSTALL_PREFIX) -DPLOG_BUILD_SAMPLES=0 && cmake --build . -j3 && cmake --install .

$(INSTALL_PREFIX)/v$(BHD_VDF_VERSION).tar.gz:
	cd $(INSTALL_PREFIX) && wget https://github.com/bhdone/bhd_vdf/archive/refs/tags/v$(BHD_VDF_VERSION).tar.gz && tar xf v$(BHD_VDF_VERSION).tar.gz && cd bhd_vdf-$(BHD_VDF_VERSION) && mkdir -p build && cd build && cmake .. -DCMAKE_INSTALL_PREFIX=$(INSTALL_PREFIX) && cmake --build . && cmake --install .

$(INSTALL_PREFIX)/$(BLS_SIGNATURES_VERSION).tar.gz:
	cd $(INSTALL_PREFIX) && wget https://github.com/Chia-Network/bls-signatures/archive/refs/tags/$(BLS_SIGNATURES_VERSION).tar.gz && tar xf $(BLS_SIGNATURES_VERSION).tar.gz && cd bls-signatures-$(BLS_SIGNATURES_VERSION) && patch -ruN -d . < ../../depends/patches/bls_signatures/001-build-as-static-library.patch && mkdir -p build && cd build && cmake .. -DCMAKE_INSTALL_PREFIX=$(INSTALL_PREFIX) && cmake --build . -j3 && cmake --install .
