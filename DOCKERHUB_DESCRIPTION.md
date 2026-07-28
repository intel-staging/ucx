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

## License

The Dockerfile for this image is licensed under **BSD-3-Clause**. Third-party
components included in the image retain their respective upstream licenses.

## Sources and Third Party Notices

This distribution includes components licensed under copyleft licenses (GPL,
LGPL, and others). The complete corresponding source code for these components
is provided in a separate sources image on Docker Hub:
**`intel/ucx-ze-builder-sources`**.

See `/sources/third-party-programs.txt` in the sources image for details on the
included components and their licenses.

- UCX source: https://github.com/openucx/ucx
- Level Zero source: https://github.com/oneapi-src/level-zero

## Reporting a security vulnerability

Report security vulnerabilities in these container images to the Intel Product
Security Incident Response Team (PSIRT):
https://www.intel.com/content/www/us/en/security-center/default.html

For vulnerabilities in UCX itself, see the upstream project:
https://github.com/openucx/ucx
