# ezpeek cloud (greenbird)

Auth + friends + presence + TCP reverse-proxy rendezvous.

## Endpoints
- API: `http://162.35.166.14:8787` (open TCP 8787 in VPS firewall)
- Relay: `162.35.166.14:8788` (open TCP 8788)
- Temporary Cloudflare tunnel may be used if ports are closed.

## Data
- `~/ezpeek-cloud-data/ezpeek.db` — SQLite
- Email columns: AES-256-GCM
- Passwords: Argon2id
- RSA keypair wraps AES master key

## Start
```bash
~/ezpeek-cloud/start.sh
```

## Security note
Open provider firewall:
- TCP 8787 (API)
- TCP 8788 (relay)
