package=toolbox
$(package)_version=3.2.6
$(package)_download_path=https://github.com/edwardstock/toolbox/archive/refs/tags
$(package)_download_file=$($(package)_version).tar.gz
$(package)_file_name=$(package)-$($(package)_version).tar.gz
$(package)_sha256_hash=445cb876dd6aa9128cabab380f0bcc62e64473e9726a263b7836a60be7f15ce9

define $(package)_fetch_cmds
$(call fetch_file,$(package),$($(package)_download_path),$($(package)_download_file),$($(package)_file_name),$($(package)_sha256_hash))
endef

define $(package)_preprocess_cmds
endef

define $(package)_config_cmds
  cmake -DENABLE_CONAN=OFF -DCMAKE_TOOLCHAIN_FILE=$(BASEDIR)/hosts/cmake/$(host).cmake -DCMAKE_INSTALL_PREFIX=$(host_prefix) .
endef

define $(package)_build_cmds
  $(MAKE)
endef

define $(package)_stage_cmds
  $(MAKE) DESTDIR=$($(package)_staging_dir) install
endef

define $(package)_postprocess_cmds
  cp lib/toolbox-3.2/libtoolbox.a lib/
endef
