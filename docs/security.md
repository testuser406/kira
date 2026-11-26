# Security notes

- **Sign-in:** argon2 password hashes, HttpOnly session cookie, rate-limited login, roles (admin / viewer), audit log
  (System tab, CSV export). Change the initial admin password after the first login.
- **Network exposure:** the dashboard (8080) and collector (5514) are plain HTTP/UDP. Keep them on the management VLAN.
  Allow only the firewall's IP in `ALLOWED_SOURCES`.
- **HTTPS:** put Kira behind a TLS reverse proxy (Caddy: `reverse_proxy 127.0.0.1:8080`; IIS ARR; nginx) and bind Kira to
  loopback by setting the API address to `127.0.0.1:8080` in `kira.env`. Then set the proxy as the only exposed port.
- **Browser hardening:** every response carries CSP, `X-Frame-Options: DENY`, `nosniff`, `Referrer-Policy: no-referrer`.
- **Privacy:** System tab > Privacy hides user names/IPs from viewers; searches and video views are deleted after 90 days.
- **Secrets:** `kira.env` holds the admin and database passwords; restrict its NTFS permissions to the service account.
- **Backups** contain all logs: store them as carefully as the live database.
- **Load test:** `python scripts/loadtest.py --eps 2000 --seconds 30` to check capacity before go-live.
