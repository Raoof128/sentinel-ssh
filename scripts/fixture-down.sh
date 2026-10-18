#!/bin/sh
docker rm -f sentinel-fixture >/dev/null 2>&1 && echo "fixture removed" || echo "no fixture running"
