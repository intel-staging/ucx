# ze-builder source-distribution artifacts

Intel-side license-compliance tooling for the `ze-builder` container image.

## What this is

`ze-builder-sources.Dockerfile` builds a companion source image that provides
the matching source code for the GPL/LGPL and other Ubuntu-archive packages
distributed in the `ze-builder` image. It is published alongside `ze-builder`
on the same Docker Hub registry, under the matching repository name with a
`-sources` suffix (e.g. `<ze-builder-repo>-sources`), so the sources are
available from a channel Intel controls, satisfying the open source
source-distribution obligations. The exact repository path is fixed when the
image is published.

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

```bash
# after ze-builder is built or pulled:
docker build -t ze-builder-sources:local \
    --build-arg ZE_BUILDER_IMAGE=ze-builder:local \
    -f ze-builder-sources.Dockerfile .
```

## Keeping in sync with ze-builder

Because the package list is derived from the `ze-builder` image at build time,
this Dockerfile only needs changes when the **base image** or the **Ubuntu
release** changes (e.g. a new `intel/oneapi-toolkit` tag, or Ubuntu 26.04).
Rebuild and re-publish the sources image whenever `ze-builder` is re-published.
