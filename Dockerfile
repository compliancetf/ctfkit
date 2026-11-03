# Runtime image for ctfkit. GoReleaser builds the static binary (CGO_ENABLED=0) and
# puts it in the build context, so nothing is compiled here and the image carries
# the same bytes as the release archives. Build it through goreleaser, not with a
# plain `docker build` from the repository root.
#
# distroless/static has no shell and no package manager; the :nonroot variant runs
# as uid 65532. The digest pins the multi-arch index, so amd64 and arm64 builds
# resolve the same release of the base. Bump it deliberately.
FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab

COPY ctfkit /usr/local/bin/ctfkit

USER nonroot:nonroot
WORKDIR /src

ENTRYPOINT ["/usr/local/bin/ctfkit"]
CMD ["--help"]
