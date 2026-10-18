#!/bin/sh
# Builds and starts the disposable sshd fixture on 127.0.0.1:2222 and writes target/fixture/fixture.env.
# The host key is read with `docker exec` (a trusted local channel), not from the network.
set -eu
cd "$(dirname "$0")/.."
umask 077
mkdir -p target/fixture
[ -f target/fixture/id_ed25519 ] || ssh-keygen -q -t ed25519 -N '' -C sentinel-fixture -f target/fixture/id_ed25519
[ -f target/fixture/wrong_host_key ] || ssh-keygen -q -t ed25519 -N '' -C wrong -f target/fixture/wrong_host_key
docker build -q --build-arg AUTHORIZED_KEY="$(cat target/fixture/id_ed25519.pub)" --build-arg LARGE="${LARGE:-0}" \
  -t sentinel-fixture crates/sentinel-testkit/docker >/dev/null
docker rm -f sentinel-fixture >/dev/null 2>&1 || true
docker run -d --name sentinel-fixture -p 127.0.0.1:2222:22 sentinel-fixture >/dev/null
tries=0
until docker exec sentinel-fixture sh -c 'test -s /etc/ssh/ssh_host_ed25519_key.pub' 2>/dev/null && nc -z 127.0.0.1 2222 2>/dev/null; do
  tries=$((tries + 1))
  [ "$tries" -lt 60 ] || { echo "fixture did not start" >&2; exit 1; }
  sleep 1
done
host_key=$(docker exec sentinel-fixture cut -d' ' -f1,2 /etc/ssh/ssh_host_ed25519_key.pub)
wrong_key=$(cut -d' ' -f1,2 target/fixture/wrong_host_key.pub)
cat > target/fixture/fixture.env <<ENV
export SENTINEL_TEST_HOST=127.0.0.1
export SENTINEL_TEST_PORT=2222
export SENTINEL_TEST_USER=sentinel
export SENTINEL_TEST_IDENTITY=$PWD/target/fixture/id_ed25519
export SENTINEL_TEST_HOST_KEY="$host_key"
export SENTINEL_TEST_WRONG_HOST_KEY="$wrong_key"
ENV
echo "fixture up: 127.0.0.1:2222 ($host_key)"
