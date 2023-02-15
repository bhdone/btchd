package=bhd_vdf
$(package)_version=v0.0.51
$(package)_download_path=https://github.com/bhdone/bhd_vdf/archive/refs/tags/
$(package)_download_file=$($(package)_version).tar.gz
$(package)_file_name=$(package)-$($(package)_version).tar.gz
$(package)_sha256_hash=67e6c93d91f3e26e25ee1b18b26cbd4f4454efa222522b5852e7c14c257ab76c

define $(package)_fetch_cmds
$(call fetch_file,$(package),$($(package)_download_path),$($(package)_download_file),$($(package)_file_name),$($(package)_sha256_hash))
endef

define $(package)_preprocess_cmds
endef

define $(package)_config_cmds
  cmake -DCMAKE_TOOLCHAIN_FILE=$(BASEDIR)/hosts/cmake/$(host).cmake -DBUILD_TEST=0 -DCMAKE_INSTALL_PREFIX=$(host_prefix) -DFETCHCONTENT_BASE_DIR=$($(package)_source_dir) .
endef

define $(package)_build_cmds
  $(MAKE)
endef

define $(package)_stage_cmds
  $(MAKE) DESTDIR=$($(package)_staging_dir) install
endef
