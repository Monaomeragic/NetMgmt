#!/bin/bash
if [ -n "$TAILSCALE_AUTHKEY" ]; then
    apt-get update -qq && apt-get install -y -qq curl
    curl -fsSL https://tailscale.com/install.sh | sh
    tailscaled --tun=userspace-networking &
    sleep 2
    tailscale up --authkey=$TAILSCALE_AUTHKEY --hostname=railway-netmgmt
    sleep 2
fi

exec gunicorn app:app --bind 0.0.0.0:$PORT
