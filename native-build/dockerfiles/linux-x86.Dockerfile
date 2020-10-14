FROM gcc:8 as build

WORKDIR /build

ARG secp256k1_rev
RUN git init && \
    git remote add origin https://github.com/bitcoin-core/secp256k1.git && \
    git fetch origin $secp256k1_rev --depth=1 && \
    git reset --hard FETCH_HEAD

RUN apt-get update
RUN apt-get install -y gcc-multilib g++-multilib libc6-dev-i386
# --host=x86_32-unknown-linux-gnu host_alias=x86_32-unknown-linux-gnu
# --host=i686-pc-linux-gnu 
RUN ./autogen.sh
# CC="gcc -m32"
# RUN ./configure CFLAGS="-Os -m32" LDFLAGS="-m32" \
RUN ./configure \
  --disable-multilib \
  --host=i686-linux-gnu \
  CFLAGS="-Os -m32" LDFLAGS="-m32" \
  --enable-experimental --enable-module-ecdh \
  --enable-module-recovery --enable-endomorphism \
  --enable-benchmark=no --enable-tests=no || cat config.log
RUN make -j$(nproc)

RUN ls -lh .libs/
RUN mkdir /out && cp -L .libs/libsecp256k1.so /out/libsecp256k1.so

FROM scratch AS export-stage
COPY --from=build /out/libsecp256k1.so /
