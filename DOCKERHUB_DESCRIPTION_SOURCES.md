# intel/ucx-ze-builder-sources

Source-code companion image for **`intel/ucx-ze-builder`**.

This image bundles the source code for the GPL/LGPL and other Ubuntu-archive
packages distributed in the `intel/ucx-ze-builder` build/CI image. It is
published so that the corresponding source is available from an Intel-controlled
channel, satisfying open source source-distribution (copyleft) obligations.

> This container image is intended for demo purposes only and not intended for
> production use. To receive expanded security maintenance from Canonical on the
> Ubuntu base layer, you may follow the how-to guide to enable Ubuntu Pro in a
> Dockerfile, which will require the image to be rebuilt.

## Contents

- Source packages (orig + debian) for the Ubuntu-archive packages shipped in
  `intel/ucx-ze-builder`, under `/sources`, fetched with `apt-get source` at the
  exact installed versions.

## Related

- Product image: **`intel/ucx-ze-builder`**
- UCX source: https://github.com/openucx/ucx
- Level Zero source: https://github.com/oneapi-src/level-zero

## Reporting a security vulnerability

Report security vulnerabilities in these container images to the Intel Product
Security Incident Response Team (PSIRT):
https://www.intel.com/content/www/us/en/security-center/default.html
