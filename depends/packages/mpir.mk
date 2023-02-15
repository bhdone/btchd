package=mpir
$(package)_version=3.0.0
$(package)_download_path=https://github.com/wbhart/mpir/archive/refs/tags
$(package)_file_name=$(package)-$($(package)_version).tar.gz
$(package)_sha256_hash=86a5039badc3e6738219a262873a1db5513405e15ece9527b718fcd0fac09bb2

define $(package)_config_cmds
    ./autogen.sh && ./configure CC_FOR_BUILD=gcc CFLAGS=-static CXXFLAGS='-static -static-libgcc -static-libstdc++' --build=x86_64-linux-gnu --host=$(host) --enable-static --disable-shared --enable-cxx --prefix=$(host_prefix)
endef

define $(package)_build_cmds
    $(MAKE)
endef

define $(package)_stage_cmds
    $(MAKE) DESTDIR=$($(package)_staging_dir) install
endef
