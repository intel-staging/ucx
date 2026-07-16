# intel/ucx-ze-builder

A Docker build/CI image for compiling and testing **UCX** with **Level Zero**
support. It is based on the Intel oneAPI toolkit (Ubuntu 24.04) and adds the
Level Zero null driver (built from upstream `oneapi-src/level-zero`) plus the
build dependencies UCX needs to configure `--with-ze`.

> **This container image is intended for demo purposes only and not intended
> for production use. To receive expanded security maintenance from Canonical
> on the Ubuntu base layer, you may follow the how-to guide to enable Ubuntu
> Pro in a Dockerfile, which will require the image to be rebuilt.**

## Intended use

- CI / build environment for UCX GPU (Level Zero) workflows.
- Not a runtime product; it ships build tooling, not a deployable service.

## Requirements

- Docker (or a compatible OCI runtime).
- x86_64 host.

## Usage

```bash
docker pull intel/ucx-ze-builder:<tag>
docker run --rm -it intel/ucx-ze-builder:<tag> bash
# inside: configure and build UCX with --with-ze
```

## Secure-by-default configuration

- The image exposes **no network services, ports, or listening interfaces** —
  it is a build environment, not a server.
- No credentials, secrets, or private keys are embedded in the image.
- No optional/remote-access interfaces are enabled.
- Network access is only used at **build time** to fetch packages and source
  over HTTPS (TLS, client-side) from the Ubuntu archive and GitHub.

## Data handling

- The image does **not** collect, store, or transmit any user or customer data.

## Updates and maintenance

- The image is rebuilt and republished with a new tag when dependencies change
  or security fixes are needed. Pull the latest tag to update; images are
  immutable per tag.

## Source code / license obligations

- Source for the open source packages distributed in this image is available in
  the companion image **`intel/ucx-ze-builder-sources`**, published on this same
  registry.
- The Dockerfile is licensed under **BSD-3-Clause**. Third-party components
  retain their respective licenses (see the companion sources image and the
  accompanying SBOM).
- UCX source: https://github.com/openucx/ucx
- Level Zero source: https://github.com/oneapi-src/level-zero

## Reporting a security vulnerability

Report security vulnerabilities in these container images to the Intel Product
Security Incident Response Team (PSIRT):
https://www.intel.com/content/www/us/en/security-center/default.html

For vulnerabilities in UCX itself, see the upstream project:
https://github.com/openucx/ucx
