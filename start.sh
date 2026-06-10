#!/bin/bash
if [ -n "$TAILSCALE_AUTHKEY" ]; then
    apt-get update -qq && apt-get install -y -qq curl
    curl -fsSL https://tailscale.com/install.sh | sh
    tailscaled --tun=userspace-networking --socks5-server=localhost:1055 --outbound-http-proxy-listen=localhost:1056 &
    sleep 2
    tailscale up --authkey=$TAILSCALE_AUTHKEY --hostname=railway-netmgmt
    sleep 3
    export HTTP_PROXY=http://localhost:1056
    export ALL_PROXY=http://localhost:1056
    export TAILSCALE_SOCKS5=localhost:1055
fi

exec gunicorn app:app --bind 0.0.0.0:$PORT
