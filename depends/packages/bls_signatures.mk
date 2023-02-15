package=chiabls
$(package)_version=1.0.7
$(package)_download_path=https://github.com/Chia-Network/bls-signatures/archive/refs/tags/
$(package)_download_file=$($(package)_version).tar.gz
$(package)_file_name=$(package)-$($(package)_version).tar.gz
$(package)_sha256_hash=eb3815dc4b7fe0630d53a6b60e58c3a6a3acc415531bcb076507271f35a674c5
$(package)_patches=001-build-as-static-library.patch

$(package)_sodium=libsodium
$(package)_sodium_version=4f5e89fa84ce1d178a6765b8b46f2b6f91216677
$(package)_sodium_download_path=https://github.com/jedisct1/libsodium/archive/
$(package)_sodium_download_file=$($(package)_sodium_version).zip
$(package)_sodium_file_name=$($(package)_sodium)-$($(package)_sodium_version).zip
$(package)_sodium_sha256_hash=e000df93ad97638217d66b5cbaa6f499d0d514516759e1ff8895bace9f006b7a

$(package)_sodium_cmake=libsodium-cmake
$(package)_sodium_cmake_version=f73a3fe1afdc4e37ac5fe0ddd401bf521f6bba65
$(package)_sodium_cmake_download_path=https://github.com/AmineKhaldi/libsodium-cmake/archive/
$(package)_sodium_cmake_download_file=$($(package)_sodium_cmake_version).zip
$(package)_sodium_cmake_file_name=$($(package)_sodium)-$($(package)_sodium_cmake_version).zip
$(package)_sodium_cmake_sha256_hash=d41e0d86c235a3d47d6a714a3049503289312430eb3dca18fb108cea81ab121c

$(package)_relic=relic
$(package)_relic_version=1d98e5abf3ca5b14fd729bd5bcced88ea70ecfd7
$(package)_relic_download_path=https://github.com/Chia-Network/relic/archive/
$(package)_relic_download_file=$($(package)_relic_version).zip
$(package)_relic_file_name=$($(package)_relic)-$($(package)_relic_version).zip
$(package)_relic_sha256_hash=d23b9488051a44deffe36df24f379a6ff259be68d7358c0ae8c43dd2ef019bd8

define $(package)_fetch_cmds
$(call fetch_file,$(package),$($(package)_download_path),$($(package)_download_file),$($(package)_file_name),$($(package)_sha256_hash)) && \
$(call fetch_file,$(package),$($(package)_sodium_download_path),$($(package)_sodium_download_file),$($(package)_sodium_file_name),$($(package)_sodium_sha256_hash)) && \
$(call fetch_file,$(package),$($(package)_sodium_cmake_download_path),$($(package)_sodium_cmake_download_file),$($(package)_sodium_cmake_file_name),$($(package)_sodium_cmake_sha256_hash)) && \
$(call fetch_file,$(package),$($(package)_relic_download_path),$($(package)_relic_download_file),$($(package)_relic_file_name),$($(package)_relic_sha256_hash))
endef

define $(package)_preprocess_cmds
  patch -p1 < $($(package)_patch_dir)/001-build-as-static-library.patch
endef

define $(package)_config_cmds
  cmake -DCMAKE_TOOLCHAIN_FILE=$(BASEDIR)/hosts/cmake/$(host).cmake -DCMAKE_INSTALL_PREFIX=$(host_prefix) -DFETCHCONTENT_BASE_DIR=$($(package)_source_dir) -DBUILD_BLS_PYTHON_BINDINGS=0 -DBUILD_BLS_TESTS=0 -DBUILD_BLS_BENCHMARKS=0 -DSODIUM_DISABLE_TESTS=1 .
endef

define $(package)_build_cmds
  $(MAKE)
endef

define $(package)_stage_cmds
  $(MAKE) DESTDIR=$($(package)_staging_dir) install
endef
