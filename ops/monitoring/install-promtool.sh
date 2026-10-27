#!/usr/bin/env bash
# Install the promtool release the monitoring artifacts are validated with into
# DIR, verifying the archive against its published SHA-256, and print its path.
set -euo pipefail
version=3.5.0
sha256=e811827af26d822afb09a4f28314f61b618b12cff5369835a67f674d8b46f39a
directory="${1:?usage: install-promtool.sh DIR}"
archive="prometheus-${version}.linux-amd64.tar.gz"
cd "$directory"
curl -fsSLO "https://github.com/prometheus/prometheus/releases/download/v${version}/${archive}"
echo "${sha256}  ${archive}" | sha256sum -c - >/dev/null
tar xzf "$archive" "prometheus-${version}.linux-amd64/promtool"
echo "$PWD/prometheus-${version}.linux-amd64/promtool"
