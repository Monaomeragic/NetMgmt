web: tailscaled --tun=userspace-networking & sleep 2 && tailscale up --authkey=$TAILSCALE_AUTHKEY --hostname=railway-netmgmt & sleep 3 && gunicorn app:app --bind 0.0.0.0:$PORT
