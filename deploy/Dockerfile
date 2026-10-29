# Multi-stage build; static musl binary, ~20 MB image.
FROM rust:1-alpine AS build
RUN apk add --no-cache musl-dev build-base
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
RUN cargo build --release --bin fairlead

FROM alpine:3.20
RUN apk add --no-cache ca-certificates tzdata
COPY --from=build /src/target/release/fairlead /usr/local/bin/fairlead
RUN adduser -D -H -s /sbin/nologin fairlead && mkdir -p /var/lib/fairlead && chown fairlead /var/lib/fairlead
USER fairlead
ENTRYPOINT ["fairlead"]
CMD ["host", "--config", "/etc/fairlead/host.toml"]
