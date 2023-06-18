FROM ubuntu:18.04

# setup zone
RUN ln -fs /usr/share/zoneinfo/Asia/Shanghai /etc/localtime

# install packages to system
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install build-essential libtool autotools-dev pkg-config make automake curl python3 patch git yasm tzdata texinfo g++-multilib binutils-gold bsdmainutils libssl-dev -y && dpkg-reconfigure --frontend noninteractive tzdata && git clone https://github.com/Kitware/CMake /cmake && cd /cmake && ./configure && make && make install

# build btchd
COPY . /btchd
RUN cd /btchd/depends && make NO_QT=1 -j3 HOST=x86_64-pc-linux-gnu
RUN cd /btchd && ./autogen.sh && ./configure --prefix=/btchd/depends/x86_64-pc-linux-gnu --with-gui=no && cd /btchd && make -j3 && mkdir -p /bhd && cp /btchd/src/btchdd /bhd && cp /btchd/src/btchd-* /bhd

FROM ubuntu:18.04

COPY --from=0 /usr/local/lib /usr/local/lib
COPY --from=0 /bhd /bhd

RUN ldconfig
