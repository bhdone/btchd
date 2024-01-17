FROM ubuntu:18.04

# setup zone
RUN ln -fs /usr/share/zoneinfo/Asia/Shanghai /etc/localtime

# install packages to system
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install build-essential libtool autotools-dev pkg-config make automake curl python3 patch git yasm tzdata texinfo g++-multilib binutils-gold bsdmainutils libssl-dev -y && dpkg-reconfigure --frontend noninteractive tzdata && git clone https://github.com/Kitware/CMake /cmake && cd /cmake && ./configure && make && make install

# build depinc
COPY . /depinc-src
RUN cd /depinc-src/depends && make NO_QT=1 -j3 HOST=x86_64-pc-linux-gnu
RUN cd /depinc-src && ./autogen.sh && ./configure --prefix=/depinc-src/depends/x86_64-pc-linux-gnu --with-gui=no && cd /depinc-src && make -j3 && mkdir -p /depinc && cp /depinc-src/src/depincd /depinc && cp /depinc-src/src/depinc-* /depinc

FROM ubuntu:18.04

COPY --from=0 /usr/local/lib /usr/local/lib
COPY --from=0 /depinc /depinc

RUN ldconfig
