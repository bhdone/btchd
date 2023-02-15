FROM ubuntu:20.04

# setup zone
RUN ln -fs /usr/share/zoneinfo/Asia/Shanghai /etc/localtime

# install packages to system
RUN apt update && apt install --yes make gcc g++ autoconf automake curl m4 libtool yasm texinfo patch lbzip2 git wget pkg-config libxml2-utils python3-dev libssl-dev bsdmainutils lzip && cd / && mkdir -p /usr/local && wget https://github.com/Kitware/CMake/releases/download/v3.24.3/cmake-3.24.3-linux-x86_64.tar.gz && tar xf cmake-3.24.3-linux-x86_64.tar.gz && cd cmake-3.24.3-linux-x86_64 && rm -rf /usr/local/man && cp -R -f * /usr/local/ && cd / && rm -rf /cmake-3.24.3-linux-x86_64.* /cmake-3.24.3-linux-x86_64 && wget https://github.com/conan-io/conan/releases/latest/download/conan-ubuntu-64.deb && dpkg -i conan-ubuntu-64.deb && rm conan-ubuntu-64.deb && conan remote list

# build btchd
COPY . /btchd
RUN cd /btchd/depends && make NO_QT=1 HOST=x86_64-pc-linux-gnu && cd /btchd && ./autogen.sh && ./configure --prefix=/btchd/depends/x86_64-pc-linux-gnu --with-gui=no --disable-asm && cd /btchd && make clean && make -j3 && mkdir -p /bhd && cp /btchd/src/btchdd /bhd && cp /btchd/src/btchd-* /bhd

# build vdf_client
RUN cd / && wget https://gmplib.org/download/gmp/gmp-6.2.1.tar.lz && tar xf gmp-6.2.1.tar.lz && cd gmp-6.2.1 && ./configure --enable-cxx && make && make install && cd / && wget https://boostorg.jfrog.io/artifactory/main/release/1.80.0/source/boost_1_80_0.tar.bz2 && tar xf boost_1_80_0.tar.bz2 && cd boost_1_80_0 && ./bootstrap.sh && ./b2 --with-system --with-thread --with-date_time --with-regex --with-serialization && ./b2 install && cd / && git clone https://github.com/chia-network/chiavdf /chiavdf && cd /chiavdf/src && make -f Makefile.vdf-client && cd / && rm -rf /boost_1_80_0.tar.bz2 /boost_1_80_0 /gmp-6.2.1 /gmp-6.2.1.tar.lz

FROM ubuntu:20.04

COPY --from=0 /usr/local/lib /usr/local/lib
COPY --from=0 /bhd /bhd
COPY --from=0 /chiavdf/src/vdf_client /

RUN ldconfig
