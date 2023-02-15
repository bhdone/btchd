package=cxxopts
$(package)_version=v3.0.0
$(package)_download_path=https://github.com/jarro2783/cxxopts/archive/refs/tags
$(package)_download_file=$($(package)_version).tar.gz
$(package)_file_name=$(package)-$($(package)_version).tar.gz
$(package)_sha256_hash=36f41fa2a46b3c1466613b63f3fa73dc24d912bc90d667147f1e43215a8c6d00

define $(package)_fetch_cmds
  $(call fetch_file,$(package),$($(package)_download_path),$($(package)_download_file),$($(package)_file_name),$($(package)_sha256_hash))
endef

define $(package)_preprocess_cmds
endef

define $(package)_config_cmds
  cmake -DCXXOPTS_BUILD_EXAMPLES=OFF -DCXXOPTS_BUILD_TESTS=OFF -DCXXOPTS_ENABLE_INSTALL=ON -DCMAKE_TOOLCHAIN_FILE=$(BASEDIR)/hosts/cmake/$(host).cmake -DCMAKE_INSTALL_PREFIX=$(host_prefix) -DFETCHCONTENT_BASE_DIR=$($(package)_source_dir) .
endef

define $(package)_build_cmds
  $(MAKE)
endef

define $(package)_stage_cmds
  $(MAKE) DESTDIR=$($(package)_staging_dir) install
endef
