FROM golang:1.26-trixie@sha256:bdca99a00bc16590cb1a0bb4e698f5fc5d6a64e4d5eef13d9f18a0ee08e5fa65 AS builder

ARG FILESTASH_REF=2ea4bae7f66b46ea51c7e81506afc7c6e0b75364

RUN apt-get update && apt-get install -y --no-install-recommends \
    git make curl \
    libjpeg-dev libtiff-dev libpng-dev libwebp-dev libraw-dev libheif-dev libgif-dev libvips-dev \
    libavcodec-dev libavdevice-dev libavfilter-dev libavformat-dev libswresample-dev libswscale-dev libavutil-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src/filestash
RUN git init && \
    git remote add origin https://github.com/mickael-kerjean/filestash.git && \
    git fetch --depth 1 origin "${FILESTASH_REF}" && \
    git checkout --detach FETCH_HEAD

COPY . /src/filestash-auth-oidc
WORKDIR /src
RUN go work init ./filestash ./filestash-auth-oidc && \
    sed -i '/_ "github.com\/mickael-kerjean\/filestash\/server\/plugin\/plg_authenticate_local"/a\	_ "github.com/eaopen/filestash-auth-oidc"' \
      filestash/server/plugin/index.go

WORKDIR /src/filestash
RUN go generate ./server/... && \
    go build --tags fts5 -o /src/filestash-bin ./cmd

FROM debian:stable-slim@sha256:5bc3287b25407c965a30f38e32603dc253a3869e1b12a21ac09bfc27fd8b13ce

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates curl ffmpeg libbrotli1 poppler-utils && \
    useradd --system --home /app --shell /usr/sbin/nologin filestash && \
    mkdir -p /app/data/state && \
    chown -R filestash:filestash /app && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY --from=builder --chown=filestash:filestash /src/filestash-bin /app/filestash
USER filestash
EXPOSE 8334
CMD ["/app/filestash"]
