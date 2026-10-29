# Multi-stage build; static musl binary, ~20 MB image.
FROM rust:1-alpine AS build
RUN apk add --no-cache musl-dev build-base
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
RUN cargo build --release --bin frplike

FROM alpine:3.20
RUN apk add --no-cache ca-certificates tzdata
COPY --from=build /src/target/release/frplike /usr/local/bin/frplike
RUN adduser -D -H -s /sbin/nologin frplike && mkdir -p /var/lib/frplike && chown frplike /var/lib/frplike
USER frplike
ENTRYPOINT ["frplike"]
CMD ["host", "--config", "/etc/frplike/host.toml"]
