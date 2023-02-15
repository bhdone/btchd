package=curl
$(package)_version=7.83.1
$(package)_download_path=https://curl.se/download
$(package)_file_name=$(package)-$($(package)_version).tar.bz2
$(package)_sha256_hash=f539a36fb44a8260ec5d977e4e0dbdd2eee29ed90fcedaa9bc3c9f78a113bff0

define $(package)_preprocess_cmds
endef

define $(package)_set_vars
  $(package)_config_opts=--with-gnutls
endef

define $(package)_config_cmds
  LDAPS=0 CPPFLAGS='-static -static-libgcc -static-libstdc++' $($(package)_autoconf) --without-nghttp2 --without-nghttp3 --without-zlib --disable-shared --disable-ldap --disable-ldaps
endef

define $(package)_build_cmds
  $(MAKE)
endef

define $(package)_stage_cmds
  $(MAKE) DESTDIR=$($(package)_staging_dir) install
endef

define $(package)_postprocess_cmds
  rm lib/*.la
endef
