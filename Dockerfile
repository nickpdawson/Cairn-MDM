# Cairn — single-binary Apple MDM server.
# Multi-stage, pure-Go (CGO off), distroless runtime with CA roots for APNs/
# OIDC/ACME egress. Runs as nonroot.

FROM golang:1.26-bookworm AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG VERSION=dev
ARG COMMIT=none
ARG DATE=unknown
RUN CGO_ENABLED=0 go build -trimpath \
    -ldflags "-s -w \
      -X github.com/dzsec/cairn-mdm/internal/version.Version=${VERSION} \
      -X github.com/dzsec/cairn-mdm/internal/version.Commit=${COMMIT} \
      -X github.com/dzsec/cairn-mdm/internal/version.Date=${DATE}" \
    -o /cairn ./cmd/cairn

FROM gcr.io/distroless/static:nonroot
LABEL org.opencontainers.image.source="https://github.com/dzsec/cairn-mdm" \
      org.opencontainers.image.description="Single-binary Apple MDM server" \
      org.opencontainers.image.licenses="MIT"
COPY --from=build /cairn /usr/local/bin/cairn
# Data dir must be a writable volume owned by the nonroot (65532) user.
VOLUME ["/var/lib/cairn"]
USER nonroot:nonroot
EXPOSE 443
ENTRYPOINT ["/usr/local/bin/cairn"]
CMD ["serve", "--config", "/etc/cairn/cairn.toml"]
