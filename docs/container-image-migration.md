# Container image compatibility and migration

## Versioning contract

`image/build.sh` builds two local tags from the version in the root `Cargo.toml`:

- `izanagi-vm:<VERSION>` is the reproducible tag for downstream images.
- `izanagi-vm:latest` is a convenience tag and may change its base OS between releases.

Downstream Dockerfiles should pin the project version, for example:

```dockerfile
FROM izanagi-vm:0.2.2
```

The base OS and libc are part of the documented image environment, but not a stable
interface of `latest`. A base-image change must be called out in release notes and in
this guide.

## Alpine 3.23 migration

The current `izanagi-vm` image uses Alpine Linux 3.23 and musl libc. Images derived
from the earlier Debian-compatible environment need these changes:

| Debian-compatible image | Alpine 3.23 image |
| --- | --- |
| `apt-get update && apt-get install ...` | `apk add --no-cache ...` |
| Debian package names | Alpine package names from the Alpine repositories |
| `rust:<version>-slim` build stage | `rust:<version>-alpine` build stage |
| `node:<version>-bookworm-slim` stage | `node:<version>-alpine` stage |
| glibc-linked copied binaries | musl-linked binaries, or packages installed inside Alpine |

Do not copy dynamically linked tools from a glibc-based stage into this image. Build
them in an Alpine/musl stage, use a static binary, or install the Alpine package.

To inspect an image before extending it:

```sh
docker run --rm izanagi-vm:0.2.2 cat /etc/os-release
docker run --rm izanagi-vm:0.2.2 ldd --version
```
