# ze-builder source-distribution artifacts

Intel-side license-compliance tooling for the `ze-builder` container image.

## What this is

`ze-builder-sources.Dockerfile` builds a companion source image that provides
the matching source code for the GPL/LGPL and other Ubuntu-archive packages
distributed in the `ze-builder` image. It is published as
`intel/ucx-ze-builder-sources` on Docker Hub, alongside the product image
`intel/ucx-ze-builder`, so the sources are available from a channel Intel
controls, satisfying the open source source-distribution obligations.

The package set is enumerated **from the built `ze-builder` image itself**
(`dpkg-query`), so the sources always match the exact versions shipped — there
is no hand-maintained package list to keep in sync.

## Scope / boundaries

- This branch is an **orphan branch** with no shared history with `master`.
- It is **not** for upstream. Do **not** merge it to `master` or open a PR to
  `openucx/ucx`.
- The product Dockerfile (`ze-builder.Dockerfile`) lives on the normal
  development branch and follows the usual upstream path; it is **not** copied
  here.

## Build

`ZE_BUILDER_IMAGE` must point at the already-built product image; its default
(`ze-builder:local`) is only a local-dev convenience and is overridden at
publish time with the real image reference.

```bash
# Local dev (product image built locally as ze-builder:local):
docker build -t ze-builder-sources:local \
    --build-arg ZE_BUILDER_IMAGE=ze-builder:local \
    -f ze-builder-sources.Dockerfile .

# Publish (product image is intel/ucx-ze-builder:<tag>):
docker build -t intel/ucx-ze-builder-sources:<tag> \
    --build-arg ZE_BUILDER_IMAGE=intel/ucx-ze-builder:<tag> \
    -f ze-builder-sources.Dockerfile .
```

## Keeping in sync with ze-builder

Because the package list is derived from the `ze-builder` image at build time,
this Dockerfile only needs changes when the **base image** or the **Ubuntu
release** changes (e.g. a new `intel/oneapi-toolkit` tag, or Ubuntu 26.04).
Rebuild and re-publish the sources image whenever `ze-builder` is re-published.
