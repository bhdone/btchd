package=utf8proc
$(package)_version=v2.7.0
$(package)_download_path=https://github.com/JuliaStrings/utf8proc/archive/refs/tags
$(package)_download_file=$($(package)_version).tar.gz
$(package)_file_name=$(package)-$($(package)_version).tar.gz
$(package)_sha256_hash=4bb121e297293c0fd55f08f83afab6d35d48f0af4ecc07523ad8ec99aa2b12a1

define $(package)_fetch_cmds
$(call fetch_file,$(package),$($(package)_download_path),$($(package)_download_file),$($(package)_file_name),$($(package)_sha256_hash))
endef

define $(package)_preprocess_cmds
endef

define $(package)_config_cmds
  mkdir -p build && cd build && cmake -DBUILD_SHARED_LIBS=0 -DCMAKE_TOOLCHAIN_FILE=$(BASEDIR)/hosts/cmake/$(host).cmake -DCMAKE_INSTALL_PREFIX=$(host_prefix) ..
endef

define $(package)_build_cmds
  cd build && $(MAKE)
endef

define $(package)_stage_cmds
  cd build && $(MAKE) DESTDIR=$($(package)_staging_dir) install
endef
