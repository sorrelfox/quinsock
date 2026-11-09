#!/usr/bin/env bash
# Builds RPM and DEB packages, each inside a container of its target distribution so
# the binary links against that distribution's glibc.
#
#   ./packaging/build.sh                 # all targets
#   ./packaging/build.sh fedora44 el9    # selected targets
#
# Output: dist/<target>/*.rpm|*.deb. Set CONTAINER_ENGINE=docker to use Docker, and
# PKG_RELEASE to change the package release number (default 1).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ENGINE="${CONTAINER_ENGINE:-podman}"
RELEASE="${PKG_RELEASE:-1}"
RUST_VERSION="$(sed -n 's/^channel *= *"\(.*\)"/\1/p' "$ROOT/rust-toolchain.toml")"

ALL=(fedora44 el9 el10 ubuntu2404 ubuntu2604 debian13)
declare -A BASE=(
    [fedora44]=registry.fedoraproject.org/fedora:44
    [el9]=quay.io/rockylinux/rockylinux:9
    [el10]=quay.io/rockylinux/rockylinux:10
    [ubuntu2404]=docker.io/library/ubuntu:24.04
    [ubuntu2604]=docker.io/library/ubuntu:26.04
    [debian13]=docker.io/library/debian:13
)
declare -A KIND=([fedora44]=rpm [el9]=rpm [el10]=rpm [ubuntu2404]=deb [ubuntu2604]=deb [debian13]=deb)
declare -A DIST=([fedora44]=.fc44 [el9]=.el9 [el10]=.el10 [ubuntu2404]="~ubuntu24.04" [ubuntu2604]="~ubuntu26.04" [debian13]="~deb13")

targets=("$@")
if [[ ${#targets[@]} -eq 0 || " ${targets[*]} " == *" all "* ]]; then
    targets=("${ALL[@]}")
fi
for t in "${targets[@]}"; do
    if [[ -z "${KIND[$t]:-}" ]]; then
        echo "unknown target '$t'; choose from: all ${ALL[*]}" >&2
        exit 2
    fi
done

for t in "${targets[@]}"; do
    kind=${KIND[$t]}
    image="quinsock-build:$t"
    out="$ROOT/dist/$t"

    echo "==> [$t] preparing build image from ${BASE[$t]}"
    "$ENGINE" build --quiet --tag "$image" \
        --build-arg BASE="${BASE[$t]}" --build-arg RUST_VERSION="$RUST_VERSION" \
        --file "$ROOT/packaging/containers/Containerfile.$kind" "$ROOT/packaging/containers" >/dev/null

    mkdir -p "$out"
    rm -f "$out"/*.rpm "$out"/*.deb
    echo "==> [$t] building ${kind} package"
    "$ENGINE" run --rm --security-opt label=disable \
        --volume "$ROOT:/src:ro" \
        --volume "$out:/out" \
        --volume "quinsock-target-$t:/build/target" \
        --volume "quinsock-cargo-registry:/opt/cargo/registry" \
        --env KIND="$kind" --env RELEASE="$RELEASE${DIST[$t]}" \
        "$image" /bin/bash /src/packaging/container-build.sh

    echo "==> [$t] done: $(cd "$out" && ls ./*."$kind")"
done
