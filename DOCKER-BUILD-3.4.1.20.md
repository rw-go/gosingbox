# Docker runtime recipe 3.4.1.20

The image and standalone package contain the same static binary, built from
clean source revision `ca0d95f15553c23fb8201f477cca38fb96bb1d99`. The shared-listener implementation
was tested on JP1 before release; the release build adds clean VCS metadata.
Publishing does not restart or upgrade existing nodes.

```sh
sha256sum -c gosingbox-3.4.1.20-linux-amd64.tar.gz.sha256
tar -xzf gosingbox-3.4.1.20-linux-amd64.tar.gz
mkdir -p docker-3.4.1.20
cp gosingbox-3.4.1.20-linux-amd64/bin/gosingbox docker-3.4.1.20/gosingbox
cp gosingbox-3.4.1.20-linux-amd64/bin/geocheck docker-3.4.1.20/geocheck
cp gosingbox-entrypoint-3.4.1.20.sh docker-3.4.1.20/gosingbox-entrypoint
cp Dockerfile-3.4.1.20 docker-3.4.1.20/Dockerfile
docker build --platform linux/amd64 --build-arg SOURCE_REVISION=ca0d95f15553c23fb8201f477cca38fb96bb1d99 -t rwnode/gosingbox:3.4.1.20 docker-3.4.1.20
```

The runtime recipe is taken from the source Dockerfile. Alpine packages may
change in later builds; the registry digest and executable SHA256 values in
`release-3.4.1.20.json` identify this publication.
