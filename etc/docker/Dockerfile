# needlefish devnet image: every binary from one `zig build`, plus the compose entrypoint.
# Build context is the repository root (see docker-compose.yml).
FROM alpine:3.20 AS build
RUN apk add --no-cache curl xz
WORKDIR /src
COPY . .
RUN etc/scripts/install-zig.sh /opt/zig && /opt/zig/zig build -Doptimize=ReleaseSafe

FROM alpine:3.20
RUN apk add --no-cache bash curl
COPY --from=build /src/zig-out/bin/ /usr/local/bin/
COPY etc/docker/entrypoint.sh /usr/local/bin/devnet-entrypoint
ENTRYPOINT ["devnet-entrypoint"]
