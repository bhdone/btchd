#!/bin/sh
CURDIR=`pwd`
echo "config dir: ${CURDIR}"

export PKG_CONFIG_PATH="/usr/local/opt/openssl@3/lib/pkgconfig"
export BDB_PREFIX="${CURDIR}/contrib/db4"

./autogen.sh && ./configure BDB_LIBS="-L${BDB_PREFIX}/lib -ldb_cxx-4.8" BDB_CFLAGS="-I${BDB_PREFIX}/include"
