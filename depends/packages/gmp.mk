package=gmp
$(package)_version=6.2.1
$(package)_download_path=https://gmplib.org/download/gmp/
$(package)_file_name=$(package)-$($(package)_version).tar.lz
$(package)_sha256_hash=2c7f4f0d370801b2849c48c9ef3f59553b5f1d3791d070cffb04599f9fc67b41

define $(package)_config_cmds
    ./configure CC_FOR_BUILD=gcc CFLAGS=-static CXXFLAGS='-static -static-libgcc -static-libstdc++' --build=x86_64-linux-gnu --host=$(host) --enable-static --disable-shared --enable-cxx --prefix=$(host_prefix)
endef

define $(package)_build_cmds
    $(MAKE)
endef

define $(package)_stage_cmds
    $(MAKE) DESTDIR=$($(package)_staging_dir) install
endef
