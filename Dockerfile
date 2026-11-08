# The binary is cross-compiled by `make` (static, CGO off); the image is just
# that binary. No shell, no libc, no config: settings come from env vars and a
# mounted config file (SPEC.md §7).
FROM scratch
ARG TARGETARCH
COPY dist/cast-relay-linux-${TARGETARCH} /cast-relay
USER 65534:65534
ENTRYPOINT ["/cast-relay"]
