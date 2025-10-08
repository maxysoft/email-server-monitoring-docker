# Build arguments (available for FROM and later stages when re-declared)
ARG TARGETOS=linux
ARG TARGETARCH=amd64
ARG BUILD_DATE=""
ARG VCS_REF=""
ARG VERSION="v0.0.0"
ARG MAINTAINER="maxysoft"

# Builder stage
FROM --platform=${TARGETOS}/${TARGETARCH} golang:1.24-alpine AS builder
RUN apk add --no-cache git ca-certificates
WORKDIR /src

# Copy go.mod and go.sum so `go mod download` can populate modules cache and be cached as a layer
COPY go.mod ./
RUN go mod download

# Copy the rest of the sources and build
COPY . .
# Set Go env from build args (fall back to sensible defaults)
ENV CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH}
RUN go build -trimpath -ldflags="-s -w" -o /out/email-server-monitoring ./main.go

# Final image stage
FROM scratch
# Re-declare build-time metadata args so they can be used in LABELs for OCI compatibility
ARG BUILD_DATE
ARG VCS_REF
ARG VERSION
ARG MAINTAINER

# OCI labels (org.opencontainers.image.*) so the image advertises metadata
LABEL org.opencontainers.image.title="email-server-monitoring"
LABEL org.opencontainers.image.description="Lightweight service to monitor mail server services and restart a docker container on failures"
LABEL org.opencontainers.image.url="https://github.com/maxysoft/email-server-monitoring-docker"
LABEL org.opencontainers.image.source="https://github.com/maxysoft/email-server-monitoring-docker"
LABEL org.opencontainers.image.version="${VERSION}"
LABEL org.opencontainers.image.created="${BUILD_DATE}"
LABEL org.opencontainers.image.revision="${VCS_REF}"
LABEL org.opencontainers.image.authors="${MAINTAINER}"
LABEL org.opencontainers.image.licenses="GPL-3.0-only"

# Copy CA certs so TLS works inside the final image
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=builder /out/email-server-monitoring /app/email-server-monitoring

# Run as non-root UID
USER 1000

WORKDIR /app
ENTRYPOINT ["/app/email-server-monitoring"]