# Copyright (C) Intel Corporation, 2026. ALL RIGHTS RESERVED.
#
# Source-code companion image for ze-builder.
#
# This is Intel-side license-compliance tooling, NOT part of UCX. It is kept
# outside the UCX source tree because upstream (openucx/ucx) has no reason to
# carry it; it exists solely to satisfy Intel's source-distribution obligation
# when the ze-builder image is published to Docker Hub.
#
# Open source distribution obligation: the ze-builder image ships GPL/LGPL
# binaries via its Ubuntu base and apt-installed packages, so the matching source
# must be made available from a channel Intel controls. This image bundles that
# source so it can be published next to ze-builder on the same registry
# (Docker Hub, Intel namespace):
#   intel/ucx-ze-builder-sources   (alongside intel/ucx-ze-builder)
# The ze-builder Docker Hub description links here and carries the Ubuntu
# demo-only / Ubuntu Pro disclaimer.
#
# The package set is enumerated FROM the ze-builder image itself so the sources
# always match the exact versions we ship (no hand-maintained list).
#
# Build (after ze-builder is built/pulled):
#   docker build -t ze-builder-sources:local \
#       --build-arg ZE_BUILDER_IMAGE=ze-builder:local \
#       -f ze-builder-sources.Dockerfile .

# The already-built product image whose packages we must provide source for.
ARG ZE_BUILDER_IMAGE=ze-builder:local

# 1. Snapshot the exact installed package list from the product image.
FROM ${ZE_BUILDER_IMAGE} AS product
RUN dpkg-query -W -f='${Package}\t${Version}\n' > /tmp/pkglist.tsv

# 2. Fetch matching source on a clean Ubuntu base with deb-src enabled.
FROM ubuntu:24.04 AS sources
COPY --from=product /tmp/pkglist.tsv /sources/pkglist.tsv

# Enable source repositories (24.04 uses the deb822 .sources format).
RUN set -eux; \
    sed -i 's/^Types: deb$/Types: deb deb-src/' \
        /etc/apt/sources.list.d/ubuntu.sources; \
    apt-get update

WORKDIR /sources
# Download source packages (orig + debian) for every Ubuntu-archive package the
# product image ships. Packages not in the Ubuntu archive (oneAPI, Intel GPU,
# Level Zero built from git) are skipped: oneAPI is Intel-proprietary and part of
# the not-redistributed base layer, and Level Zero source is provided separately
# (built from a public tag recorded in ze-builder.Dockerfile). apt-get source is
# best-effort per package so a non-archive name does not fail the whole build.
RUN set -eux; \
    while IFS="$(printf '\t')" read -r pkg ver; do \
        [ -n "${pkg}" ] || continue; \
        echo "=== source: ${pkg}=${ver} ==="; \
        apt-get source --download-only "${pkg}=${ver}" \
            || apt-get source --download-only "${pkg}" \
            || echo "SKIP ${pkg}: no source in Ubuntu archive (non-archive/proprietary)"; \
    done < pkglist.tsv; \
    ls -1 /sources | sed -n '1,20p'; \
    echo "Total source files: $(ls -1 /sources | wc -l)"

# 3. Final image: just the collected sources + the package manifest.
FROM ubuntu:24.04
LABEL org.opencontainers.image.description="Source code for GPL/LGPL and other \
Ubuntu-archive packages distributed in the ze-builder image. Provided to satisfy \
open source license obligations. Demo purposes only, not for production use."
COPY --from=sources /sources /sources
WORKDIR /sources
