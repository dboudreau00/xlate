# Build a static binary, then ship it on a base with nothing else on it.
# The admin console is embedded, so the final image is one file plus certs.
# golang:1.26-alpine
FROM golang@sha256:3082400e369fa24d5fc60bca20edab3f6d604e0c5a690ec66b295eff4dd87ade AS build
WORKDIR /src

# Nothing outside the standard library, so there is nothing to download —
# copy the source and build. (.dockerignore keeps state files, archives
# and binaries out of the context; the state file holds credentials.)
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/xlate . \
    && mkdir -p /out/data

# gcr.io/distroless/static-debian12:nonroot
FROM gcr.io/distroless/static-debian12@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab
COPY --from=build /out/xlate /usr/local/bin/xlate

# State and audit trail live here; mount a volume so they survive the
# container. The directory must be owned by the runtime uid (65532,
# distroless "nonroot") BEFORE the volume is declared — a named volume
# copies the image's ownership on first use, and a root-owned 0755 dir
# would make the very first OpenAudit fail EACCES and crash-loop the
# container. (Bind mounts don't get this copy: chown the host dir to
# 65532 yourself.)
COPY --from=build --chown=65532:65532 /out/data /var/lib/xlate
VOLUME ["/var/lib/xlate"]
WORKDIR /var/lib/xlate
USER nonroot:nonroot
EXPOSE 8080

# XLATE_ADMIN_TOKEN must be supplied; without it a token is generated per
# run and printed to the log, which is not what you want in a container
# that may restart.
ENTRYPOINT ["/usr/local/bin/xlate"]
CMD ["-listen", ":8080", \
     "-state", "/var/lib/xlate/state.json", \
     "-audit", "/var/lib/xlate/trail.jsonl"]
