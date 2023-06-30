INSTALL_PREFIX=$(shell pwd)
DB4_VERSION=4.8.30
PLOG_VERSION=1.1.9
BHD_VDF_VERSION=0.0.57
BLS_SIGNATURES_VERSION=1.0.7

all: db-$(DB4_VERSION).NC.tar.gz $(PLOG_VERSION).tar.gz v$(BHD_VDF_VERSION).tar.gz $(BLS_SIGNATURES_VERSION).tar.gz

db-$(DB4_VERSION).NC.tar.gz:
	CFLAGS="-Wno-error=implicit-function-declaration" ../../contrib/install_db4.sh .

$(PLOG_VERSION).tar.gz:
	wget https://github.com/SergiusTheBest/plog/archive/refs/tags/$(PLOG_VERSION).tar.gz && tar xf $(PLOG_VERSION).tar.gz && cd plog-$(PLOG_VERSION) && cmake . -DCMAKE_INSTALL_PREFIX=$(INSTALL_PREFIX) -DPLOG_BUILD_SAMPLES=0 && cmake --build . -j3 && cmake --install .

v$(BHD_VDF_VERSION).tar.gz:
	wget https://github.com/bhdone/bhd_vdf/archive/refs/tags/v$(BHD_VDF_VERSION).tar.gz && tar xf v$(BHD_VDF_VERSION).tar.gz && cd bhd_vdf-$(BHD_VDF_VERSION) && mkdir -p build && cd build && cmake .. -DCMAKE_INSTALL_PREFIX=$(INSTALL_PREFIX) && cmake --build . && cmake --install .

$(BLS_SIGNATURES_VERSION).tar.gz:
	wget https://github.com/Chia-Network/bls-signatures/archive/refs/tags/$(BLS_SIGNATURES_VERSION).tar.gz && tar xf $(BLS_SIGNATURES_VERSION).tar.gz && cd bls-signatures-$(BLS_SIGNATURES_VERSION) && patch -ruN -d . < $(INSTALL_PREFIX)/../../depends/patches/bls_signatures/001-build-as-static-library.patch && mkdir -p build && cd build && cmake .. -DCMAKE_INSTALL_PREFIX=$(INSTALL_PREFIX) && cmake --build . -j3 && cmake --install .
