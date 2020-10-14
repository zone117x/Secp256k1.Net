FROM gcc:8 as build

WORKDIR /build

ARG secp256k1_rev
RUN git init && \
    git remote add origin https://github.com/bitcoin-core/secp256k1.git && \
    git fetch origin $secp256k1_rev --depth=1 && \
    git reset --hard FETCH_HEAD

RUN apt-get update
RUN apt-get install -y gcc-mingw-w64-i686

RUN echo "LDFLAGS = -no-undefined" >> Makefile.am
RUN ./autogen.sh
RUN ./configure CFLAGS="-Os" --host=i686-w64-mingw32 \
  --enable-experimental --enable-module-ecdh \
  --enable-module-recovery --enable-endomorphism \
  --enable-benchmark=no --enable-tests=no
RUN make -j$(nproc)

RUN ls .libs/
RUN mkdir /out && cp .libs/libsecp256k1-0.dll /out/secp256k1.dll

FROM scratch AS export-stage
COPY --from=build /out/secp256k1.dll /
