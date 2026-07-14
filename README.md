# ezpeek-svr

Cloud backend for [ezpeek](https://github.com/RishiSpace/ezpeek): auth, friends, presence, **TCP reverse-proxy**, and **STUN/TURN**.

Clients **dial out only** — end users do not need to open inbound firewall ports on their PCs. Only this server needs public ports.

## Features

- **Auth** — register / login (username or email + password)
- **SQLite** data store with:
  - **Argon2id** password hashes
  - **AES-256-GCM** encrypted emails at rest
  - **RSA** keypair wrapping the AES master key
- **Friends** — add / accept / list
- **Presence** — online, hosting, LAN IPs, ports, relay ready
- **TCP reverse-proxy (8788)** — host and viewer dial out; server pairs **control** and **video** streams
- **STUN (3478/udp)** — public address discovery
- **TURN (3478/udp)** — UDP relay for NAT that cannot hole-punch (enabled by default)

## Ports (server-side only)

| Port | Proto | Role |
|------|--------|------|
| **8787** | TCP | HTTP API |
| **8788** | TCP | Reverse-proxy relay (control + video) |
| **3478** | UDP | STUN (+ TURN signaling / allocations) |
| **49152–65535** | UDP | TURN media relay range (when TURN is used) |

Open these on the VPS / security group. **Clients need zero inbound rules** for cloud remoting.

## Run

```bash
python3 -m venv venv
source venv/bin/activate   # or uv venv + uv pip install
pip install -r requirements.txt

export EZPEEK_DATA=$HOME/ezpeek-cloud-data
export EZPEEK_JWT_SECRET=$(openssl rand -hex 32)   # persist this in production
export EZPEEK_PUBLIC_HOST=your.public.ip.or.dns
export PYTHONPATH=$PWD
# optional:
# export EZPEEK_TURN_ENABLED=1          # default on
# export EZPEEK_TURN_PASSWORD=...       # else persisted under EZPEEK_DATA/turn.password
# export EZPEEK_STUN_PORT=3478

python -m uvicorn ezpeek_cloud.app:app --host 0.0.0.0 --port 8787
```

- **API:** `http://0.0.0.0:8787` (`/health`, `/docs`, `/auth/*`, `/friends/*`, `/presence`, **`/ice`**)
- **Relay:** TCP **8788**
- **STUN/TURN:** UDP **3478**

### Firewall

```bash
sudo ufw allow 8787/tcp comment 'ezpeek API'
sudo ufw allow 8788/tcp comment 'ezpeek TCP relay'
sudo ufw allow 3478/udp comment 'ezpeek STUN/TURN'
# If TURN media is used heavily, also allow the high UDP range:
# sudo ufw allow 49152:65535/udp comment 'ezpeek TURN media'
```

Also open the same ports on the cloud provider security group if applicable.

## Environment

| Variable | Default | Meaning |
|----------|---------|---------|
| `EZPEEK_DATA` | `~/ezpeek-cloud-data` | DB + crypto keys + turn.password |
| `EZPEEK_JWT_SECRET` | random each run if unset | JWT signing (set stably!) |
| `EZPEEK_PUBLIC_HOST` | (set me) | Host/IP returned for relay & ICE URLs |
| `EZPEEK_API_PORT` | `8787` | HTTP API port |
| `EZPEEK_RELAY_PORT` | `8788` | TCP reverse-proxy port |
| `EZPEEK_STUN_PORT` | `3478` | STUN/TURN UDP port |
| `EZPEEK_TURN_ENABLED` | `1` | Enable TURN allocations |
| `EZPEEK_TURN_REALM` | `ezpeek` | TURN realm |
| `EZPEEK_TURN_USER` | `ezpeek` | TURN long-term username |
| `EZPEEK_TURN_PASSWORD` | auto file | TURN long-term password |

## ICE config

Logged-in clients call **`GET /ice`** for:

- STUN URLs
- TURN URLs + credentials
- TCP relay host/port

Primary remoting path for friends across NATs is the **TCP reverse-proxy** (reliable, no client ports). STUN/TURN support discovery and optional UDP relay.

## License

See [LICENSE](LICENSE).
