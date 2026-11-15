# Docker runtime recipe 3.4.1.19

The published image uses the exact static binaries from the standalone package.
Source revision: `ff7a486e2c6ded22df983577b129d2b38eca8c72`.

```sh
sha256sum -c gosingbox-3.4.1.19-linux-amd64.tar.gz.sha256
mkdir -p docker-3.4.1.19
tar -xzf gosingbox-3.4.1.19-linux-amd64.tar.gz
cp gosingbox-3.4.1.19-linux-amd64/bin/gosingbox docker-3.4.1.19/gosingbox
cp gosingbox-3.4.1.19-linux-amd64/bin/geocheck docker-3.4.1.19/geocheck
cp gosingbox-entrypoint-3.4.1.19.sh docker-3.4.1.19/gosingbox-entrypoint
cp Dockerfile-3.4.1.19 docker-3.4.1.19/Dockerfile
docker build --platform linux/amd64 --build-arg SOURCE_REVISION=ff7a486e2c6ded22df983577b129d2b38eca8c72 -t rwnode/gosingbox:3.4.1.19 docker-3.4.1.19
```

The recipe shares the source Dockerfile runtime. Rebuilding later may pick up changed Alpine packages; the registry digest identifies the tested publication exactly. Reproduce the executable payload by verifying the SHA256 values in `release-3.4.1.19.json`.
