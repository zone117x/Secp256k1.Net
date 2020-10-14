FROM liushuyu/osxcross as build

WORKDIR /build

ARG secp256k1_rev
RUN git init && \
    git remote add origin https://github.com/bitcoin-core/secp256k1.git && \
    git fetch origin $secp256k1_rev --depth=1 && \
    git reset --hard FETCH_HEAD

RUN apt-get update
RUN apt-get install -y autoconf libtool

RUN ./autogen.sh
RUN ./configure CFLAGS="-Os" \
  CC=x86_64-apple-darwin18-cc --host=x86_64-apple-darwin18 \
  --enable-experimental --enable-module-ecdh \
  --enable-module-recovery --enable-endomorphism \
  --enable-benchmark=no --enable-tests=no --enable-exhaustive-tests=no
RUN make -j$(nproc)

RUN ls -lh .libs/
RUN mkdir /out && cp -L .libs/libsecp256k1.dylib /out/libsecp256k1.dylib

FROM scratch AS export-stage
COPY --from=build /out/libsecp256k1.dylib /
