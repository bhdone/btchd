package=bip3x
$(package)_version=2.2.0
$(package)_download_path=https://github.com/edwardstock/bip3x/archive/refs/tags
$(package)_file_name=$($(package)_version).tar.gz
$(package)_sha256_hash=827abfe28ff7f184396c6b3047626a91a4eab79e025a20d5a53c82b44e0d6311

define $(package)_config_cmds
    cmake -DENABLE_BIP39_JNI=0 -DENABLE_BIP39_C=0 -DUSE_OPENSSL_RANDOM=1 -DCMAKE_TOOLCHAIN_FILE=$(BASEDIR)/hosts/cmake/$(host).cmake -DCMAKE_INSTALL_PREFIX=$(host_prefix) .
endef

define $(package)_build_cmds
    $(MAKE)
endef

define $(package)_stage_cmds
    $(MAKE) DESTDIR=$($(package)_staging_dir) install
endef

define $(package)_postprocess_cmds
  cp lib/bip3x-2.2/libbip39.a lib/
endef
