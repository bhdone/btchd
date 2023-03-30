#!/bin/sh
export PKG_CONFIG_PATH="/usr/local/opt/openssl@3/lib/pkgconfig"
export BDB_PREFIX="$HOME/Workspace/BitcoinHD/btchd/db4"
./configure BDB_LIBS="-L${BDB_PREFIX}/lib -ldb_cxx-4.8" BDB_CFLAGS="-I${BDB_PREFIX}/include"
