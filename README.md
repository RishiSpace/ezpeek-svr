# ezpeek-svr

Cloud backend for [ezpeek](https://github.com/RishiSpace/ezpeek): auth, friends, presence, and TCP reverse-proxy rendezvous.

## Features

- **Auth** — register / login (username or email + password)
- **SQLite** data store with:
  - **Argon2id** password hashes
  - **AES-256-GCM** encrypted emails at rest
  - **RSA** keypair wrapping the AES master key
- **Friends** — add / accept / list
- **Presence** — online, hosting, LAN IPs, ports, relay ready
- **Relay** — host and viewer dial out; server pairs TCP streams

## Run

```bash
python3 -m venv venv
source venv/bin/activate   # or uv venv + uv pip install
pip install -r requirements.txt

export EZPEEK_DATA=$HOME/ezpeek-cloud-data
export EZPEEK_JWT_SECRET=$(openssl rand -hex 32)   # persist this in production
export EZPEEK_PUBLIC_HOST=your.public.ip.or.dns
export PYTHONPATH=$PWD

python -m uvicorn ezpeek_cloud.app:app --host 0.0.0.0 --port 8787
```

- **API:** `http://0.0.0.0:8787` (`/health`, `/docs`, `/auth/*`, `/friends/*`, `/presence`)
- **Relay:** TCP port **8788** (started with the API process)

### Firewall

```bash
sudo ufw allow 8787/tcp comment 'ezpeek API'
sudo ufw allow 8788/tcp comment 'ezpeek relay'
```

Also open the same ports on the cloud provider security group if applicable.

## Environment

| Variable | Default | Meaning |
|----------|---------|---------|
| `EZPEEK_DATA` | `~/ezpeek-cloud-data` | DB + crypto keys |
| `EZPEEK_JWT_SECRET` | random each run if unset | JWT signing (set stably!) |
| `EZPEEK_PUBLIC_HOST` | `162.35.166.14` | Host string returned for relay |
| `EZPEEK_API_PORT` | `8787` | HTTP API port |
| `EZPEEK_RELAY_PORT` | `8788` | TCP relay port |

## License

See [LICENSE](LICENSE).
