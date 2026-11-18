# syntax=docker/dockerfile:1
# Multi-stage build for Presswork (CUPS-compatible print spooler in Rust).
#
# Production builds can pin base images by digest via build args, e.g.:
#   docker build \
#     --build-arg RUST_IMAGE=rust:1.88-bookworm@sha256:... \
#     --build-arg RUNTIME_IMAGE=debian:bookworm-slim@sha256:... \
#     --build-arg INSTALL_CUPS_FILTERS=true .

ARG RUST_IMAGE=rust:1.88-bookworm
ARG RUNTIME_IMAGE=debian:bookworm-slim

FROM ${RUST_IMAGE} AS builder

# Ensure deterministic lp UID/GID (631:631) matching the runtime stage.
# Debian base-passwd pre-creates lp (7:7), so reassign if present.
RUN if getent group lp >/dev/null 2>&1; then \
      groupmod --gid 631 lp; \
    else \
      groupadd --system --gid 631 lp; \
    fi \
 && if id lp >/dev/null 2>&1; then \
      usermod --uid 631 --gid 631 --home /var/spool/cups --shell /usr/sbin/nologin lp; \
    else \
      useradd --system --uid 631 --gid 631 --no-create-home \
        --home-dir /var/spool/cups --shell /usr/sbin/nologin lp; \
    fi

WORKDIR /src
COPY . .

RUN cargo build --workspace --release --locked \
 && make install-files DESTDIR=/stage PROFILE=release CHOWN=0

FROM ${RUNTIME_IMAGE}

ARG VERSION=0.1.0
ARG REVISION=unknown
ARG CREATED=unknown
# Set --build-arg INSTALL_CUPS_FILTERS=true to bundle OpenPrinting cups-filters
# (pstops, pdftopdf, rastertopwg, etc.) for non-driverless / legacy printers.
ARG INSTALL_CUPS_FILTERS=false

LABEL org.opencontainers.image.title="presswork" \
      org.opencontainers.image.description="Memory-safe, CUPS-compatible print spooler and IPP scheduler in Rust" \
      org.opencontainers.image.url="https://github.com/vindeckyy/presswork" \
      org.opencontainers.image.source="https://github.com/vindeckyy/presswork" \
      org.opencontainers.image.documentation="https://vindeckyy.github.io/presswork/" \
      org.opencontainers.image.licenses="Apache-2.0 OR MIT" \
      org.opencontainers.image.vendor="Presswork" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${REVISION}" \
      org.opencontainers.image.created="${CREATED}"

# Install CA certificates (required for ipps:// TLS backends) and optionally
# cups-filters. Install libcap2-bin transiently to grant CAP_NET_BIND_SERVICE
# to /usr/sbin/cupsd so the container runs cleanly as non-root UID 631.
RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      ca-certificates \
      libcap2-bin \
      $(if [ "${INSTALL_CUPS_FILTERS}" = "true" ]; then echo "cups-filters"; fi) \
 && if getent group lp >/dev/null 2>&1; then \
      groupmod --gid 631 lp; \
    else \
      groupadd --system --gid 631 lp; \
    fi \
 && if id lp >/dev/null 2>&1; then \
      usermod --uid 631 --gid 631 --home /var/spool/cups --shell /usr/sbin/nologin lp; \
    else \
      useradd --system --uid 631 --gid 631 --no-create-home \
        --home-dir /var/spool/cups --shell /usr/sbin/nologin lp; \
    fi \
 && (getent group lpadmin >/dev/null 2>&1 || groupadd --system lpadmin) \
 && rm -rf /var/lib/apt/lists/*

COPY --from=builder /stage /

# Inside a container, published traffic arrives on the container interface rather
# than loopback; interface exposure is controlled by the host publish flag
# (e.g. 127.0.0.1:8631:631) or Kubernetes Service/NetworkPolicy.
RUN sed -i 's/^Listen localhost:631/Listen 0.0.0.0:631/' /etc/cups/cupsd.conf \
 && setcap 'cap_net_bind_service=+ep' /usr/sbin/cupsd \
 && apt-get purge -y --auto-remove libcap2-bin \
 && rm -rf /var/lib/apt/lists/* \
 && mkdir -p /etc/cups/ssl /var/spool/cups/tmp /var/log/cups /var/cache/cups/rss /run/cups/certs \
 && chown -R 631:631 /etc/cups /var/spool/cups /var/log/cups /var/cache/cups /run/cups \
 && chmod 0700 /etc/cups/ssl \
 && chmod 0710 /var/spool/cups /var/spool/cups/tmp \
 && chmod 0770 /var/cache/cups /var/cache/cups/rss \
 && chmod 0755 /var/log/cups /run/cups /run/cups/certs

EXPOSE 631
VOLUME ["/etc/cups", "/var/spool/cups", "/var/log/cups"]

# Probe http://127.0.0.1:631/healthz over /dev/tcp with zero extra runtime
# packages; accepts 200 OK and falls back to 404 (TCP+HTTP alive) on builds
# without /healthz, failing on connection refused or 5xx.
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD ["/bin/bash", "-c", "exec 3<>/dev/tcp/127.0.0.1/631 && printf 'GET /healthz HTTP/1.1\\r\\nHost: localhost\\r\\nConnection: close\\r\\n\\r\\n' >&3 && IFS= read -r status <&3 && case \"$status\" in *' 200 '*|*' 404 '*) exit 0 ;; *) exit 1 ;; esac"]

# Least-privilege non-root runtime as lp (631:631).
USER 631:631

ENTRYPOINT ["/usr/sbin/cupsd", "-f"]
