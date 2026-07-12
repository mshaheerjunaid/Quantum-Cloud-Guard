# Hosting Quantum Cloud Guard on a Cloud VPS: Start to Finish

This is a complete, plain-language walkthrough for putting QCG KMS on the public
internet so your team can reach it from their own computers. It assumes you've
already run it locally and now want it "live."

You do **not** need to be a systems expert. Follow the steps in order, one command
at a time, and you'll end with a working `https://kms.yourcompany.com`.

---

## 1. The big picture (what you're building)

You're going to run three small pieces on one server:

1. **Caddy**, a tiny web server that owns the public HTTPS address and gets a
   real TLS certificate for your domain automatically. It's the front door.
2. **Sentinel Gate**, your security gateway (blocks floods/abuse, rate-limits,
   and optionally checks the device's certificate). It sits behind Caddy.
3. **QCG KMS**, the key service itself. It listens only on the server's *inside*
   (localhost), so the outside world can never talk to it directly, only through
   the gateway.

The flow of a request: **Employee's browser/CLI → Caddy (HTTPS) → Sentinel Gate
→ QCG KMS**.

> **Two honest options.** Getting Caddy → KMS working is straightforward and
> proven. Inserting Sentinel Gate in the middle is the integration step we should
> validate together the first time. So this guide gives you **Option A (Caddy →
> KMS, live fast)** and then **Option B (add Sentinel Gate in front)**. Start with
> A, confirm it works, then layer in B.

---

## 2. What you need before you start

- A **VPS** (a rented Linux server). Section 3 helps you pick one.
- A **domain name** (e.g. `yourcompany.com`) so you can use a real HTTPS address
  like `kms.yourcompany.com`. Cheap registrars: Cloudflare, Namecheap, Porkbun.
- The **QCG KMS zip** (the file you already have).
- About **30–45 minutes**.

Throughout, replace `kms.yourcompany.com` with your real subdomain and
`you@server` with your server's address.

---

## 3. Choosing a VPS: from free to best

Any provider works; you just need Ubuntu 24.04 (or 22.04), ~1 GB RAM minimum
(2 GB comfortable). Here's the honest landscape, cheapest first:

| Tier | Provider & plan | Rough price | Why / notes |
|------|------------------|-------------|-------------|
| **Free** | **Oracle Cloud, Always Free** (Ampere Arm, up to 4 cores / 24 GB) | $0 forever | The most generous free tier by far; genuinely enough to run all of this. Needs a card for identity check. Setup is fiddlier than others. |
| Free | Google Cloud `e2-micro` free VM / AWS Free Tier `t3.micro` (12 months) | $0 (limited) | Fine for testing; small; AWS only free for the first year. |
| **Economical (best value)** | **Hetzner Cloud `CX22`** (2 vCPU / 4 GB) | ~€3.79/mo | Excellent performance per euro, very reliable. EU + US regions. Pays by card/PayPal. My top pick if a small monthly cost is OK. |
| Economical | DigitalOcean Basic Droplet (1–2 GB) | $4–6/mo | The easiest, friendliest dashboard and docs; great for first-timers. |
| Economical | Vultr / Linode (Akamai) (1–2 GB) | $5/mo | Many regions (incl. ones closer to South Asia: Singapore, Mumbai-adjacent, etc.), good for lower latency. |
| Economical | Contabo VPS | ~$5–7/mo | Lots of RAM for the money; performance is more variable. |
| **Mid** | DigitalOcean / Vultr / Linode 4–8 GB | $12–40/mo | When you have real users and want headroom. |
| **Best / serious** | AWS Lightsail → EC2, GCP, Azure | $5 → up | For scale, compliance, managed backups, multi-region. More moving parts. |

**If you're in Pakistan / South Asia:** pick a *nearby region* for speed, Vultr
and Linode have Singapore and India-area locations, AWS has Mumbai (`ap-south-1`)
and Bahrain, Oracle has Mumbai and UAE. For payment, an international debit/credit
card or PayPal works with Hetzner/DigitalOcean/Vultr; Oracle's free tier needs a
card only for verification.

**My recommendation:** start on **Oracle Always Free** if you want zero cost, or
**Hetzner CX22** if a few euros a month is fine and you want the smoothest, fastest
experience. Both are plenty for this.

---

## 4. Create the server

In your provider's dashboard:
1. Create a new instance/droplet/VM.
2. Choose **Ubuntu 24.04 LTS**.
3. Pick the region closest to your users.
4. For login, choose **SSH key** if offered (more secure). If you only have a
   password, that's fine to start.
5. Create it, and note the server's **public IP address** (e.g. `203.0.113.10`).

Connect to it from your own machine (Kali, Mac, or Windows PowerShell):
```bash
ssh root@203.0.113.10
```
(Accept the fingerprint prompt the first time.)

---

## 5. Lock the server down (do this before anything else)

Run these on the server, one block at a time.

Create a normal user (don't run things as root) and give it sudo:
```bash
adduser deploy
usermod -aG sudo deploy
```
Update everything:
```bash
apt update && apt -y upgrade
```
Turn on the firewall, allow only SSH and web:
```bash
apt -y install ufw
ufw allow OpenSSH
ufw allow 80
ufw allow 443
ufw --force enable
```
Add basic brute-force protection for SSH:
```bash
apt -y install fail2ban
systemctl enable --now fail2ban
```
From here on, log in as `deploy` (open a new terminal):
```bash
ssh deploy@203.0.113.10
```

---

## 6. Point your domain at the server

In your domain registrar's DNS settings, add an **A record**:

- **Name/Host:** `kms` (this makes `kms.yourcompany.com`)
- **Value/Points to:** your server's public IP (`203.0.113.10`)
- **TTL:** default

Wait a few minutes, then check from your laptop:
```bash
ping kms.yourcompany.com
```
It should resolve to your server's IP. (DNS can take anywhere from minutes to an
hour.) You need this working before TLS will succeed.

---

## 7. Install the basics on the server

```bash
sudo apt -y install python3 python3-venv python3-pip redis-server unzip
```
Start Redis (Sentinel Gate uses it) and confirm it answers:
```bash
sudo systemctl enable --now redis-server
redis-cli ping            # should print: PONG
```

---

## 8. Deploy the KMS (Option A: live fast)

Upload the zip from your laptop to the server (run this on your **laptop**):
```bash
scp ~/Downloads/QCG-KMS-v1.5.1.zip deploy@203.0.113.10:~/
```
Back on the **server**, unpack and install it:
```bash
cd ~
unzip QCG-KMS-v1.5.1.zip
cd qcg
python3 -m venv .venv
. .venv/bin/activate
pip install -e .
```

**Generate your real master key** (this protects all stored private keys, guard
it like the crown jewels):
```bash
python -c "import base64,os; print(base64.b64encode(os.urandom(32)).decode())"
```
Copy the line it prints. **Back it up somewhere safe and offline** (a password
manager). If you lose it, you lose access to everything encrypted under it.

Create a folder for the database on disk:
```bash
sudo mkdir -p /var/lib/qcg
sudo chown deploy:deploy /var/lib/qcg
```

Now create a **systemd service** so the KMS runs in the background and restarts on
reboot. Create the file:
```bash
sudo nano /etc/systemd/system/qcg-kms.service
```
Paste this (replace `PASTE_YOUR_MASTER_KEY` and the host), then save (Ctrl+O,
Enter, Ctrl+X):
```ini
[Unit]
Description=QCG KMS
After=network.target

[Service]
User=deploy
WorkingDirectory=/home/deploy/qcg
Environment=QCG_ENVIRONMENT=production
Environment=QCG_HOST=127.0.0.1
Environment=QCG_PORT=8800
Environment=QCG_DB_PATH=/var/lib/qcg/qcg.db
Environment=QCG_MASTER_KEY=PASTE_YOUR_MASTER_KEY
Environment=QCG_ALLOWED_HOSTS=kms.yourcompany.com
Environment=QCG_REQUIRE_CHECKOUT=true
Environment=QCG_CHECKOUT_TTLS={"technician":900,"engineer":3600,"manager":7200,"admin":28800}
ExecStart=/home/deploy/qcg/.venv/bin/python -m qcg_kms
Restart=on-failure

[Install]
WantedBy=multi-user.target
```
Start it:
```bash
sudo systemctl daemon-reload
sudo systemctl enable --now qcg-kms
sudo systemctl status qcg-kms      # should say "active (running)"
```
The KMS is now running, but only on `127.0.0.1:8800` (private). Next we give it a
public HTTPS front door.

### TLS front door with Caddy
Install Caddy:
```bash
sudo apt -y install debian-keyring debian-archive-keyring apt-transport-https curl
curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' | sudo gpg --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg
curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt' | sudo tee /etc/apt/sources.list.d/caddy-stable.list
sudo apt update && sudo apt -y install caddy
```
Tell Caddy about your site:
```bash
sudo nano /etc/caddy/Caddyfile
```
Replace the contents with (Option A, straight to the KMS):
```
kms.yourcompany.com {
    reverse_proxy 127.0.0.1:8800
}
```
Reload Caddy:
```bash
sudo systemctl reload caddy
```
Caddy will automatically fetch a free Let's Encrypt certificate (this is why the
DNS in step 6 had to be working). Give it ~30 seconds, then from your **laptop**:
```
open https://kms.yourcompany.com   # or just visit it in a browser
```
You should see the **Create administrator account** screen, over real HTTPS. 🎉

You now have a working, secured deployment. Create your admin, and you can already
invite your team. If you want the extra protection layer, continue to Option B.

---

## 9. Add Sentinel Gate in front (Option B)

This inserts your gateway between Caddy and the KMS, so all traffic is
rate-limited and abuse-filtered, with optional device-certificate checks. It
also lights up the **Live Monitor** dashboard inside the KMS console, because
the dashboard is fed by Sentinel Gate.

The end goal looks like this:

    Browser / qcg client
            |
          Caddy            (public HTTPS, port 443)
            |
      Sentinel Gate        (127.0.0.1:8080, filters and watches traffic)
            |
         QCG KMS           (127.0.0.1:8800, private, never exposed directly)

### 9.1 Install the gateway

Upload and install it (on your **laptop** then **server**):
```bash
# laptop:
scp ~/Downloads/Sentinel-Gate-QCG.zip deploy@203.0.113.10:~/
```
```bash
# server:
cd ~ && unzip Sentinel-Gate-QCG.zip && cd sentinel-gate-qcg
python3 -m venv .venv && . .venv/bin/activate && pip install -e .
```

### 9.2 Pick one shared admin token

The gateway has an admin token that protects its admin endpoints (ban, unban,
and the live telemetry the dashboard reads). The KMS needs that same token so it
can fetch the dashboard data on your behalf. Generate one now and keep it handy,
you will paste it into two places:
```bash
python3 -c "import secrets; print(secrets.token_urlsafe(32))"
```
Call the result your SENTINEL_ADMIN_TOKEN.

### 9.3 Create the gateway service

```bash
sudo nano /etc/systemd/system/sentinel-gate.service
```
Paste this. It runs the gateway on `127.0.0.1:8080`, forwards clean traffic to
the KMS on `127.0.0.1:8800`, turns demo routes off, and switches on the
connection enrichment that powers the dashboard:
```ini
[Unit]
Description=Sentinel Gate QCG
After=network.target redis-server.service

[Service]
User=deploy
WorkingDirectory=/home/deploy/sentinel-gate-qcg
Environment=SENTINEL_ENVIRONMENT=production
Environment=SENTINEL_REDIS_URL=redis://localhost:6379/0
Environment=SENTINEL_TRUSTED_HOSTS=kms.yourcompany.com
Environment=SENTINEL_TRUSTED_PROXIES=127.0.0.1/32
Environment=SENTINEL_ENABLE_DEMO_ROUTES=false
Environment=SENTINEL_UPSTREAM_URL=http://127.0.0.1:8800
Environment=SENTINEL_ADMIN_TOKEN=PASTE_THE_TOKEN_FROM_9.2
Environment=SENTINEL_GEO_ENABLED=true
Environment=SENTINEL_NETWORK_CLASSIFY_ENABLED=true
ExecStart=/home/deploy/sentinel-gate-qcg/.venv/bin/python -m sentinel_gate_qcg --host 127.0.0.1 --port 8080
Restart=on-failure

[Install]
WantedBy=multi-user.target
```
> Confirm the exact upstream and launch flags in the gateway's `GUIDE.md`. The
> settings above (`SENTINEL_UPSTREAM_URL`, host, and port) are the ones to check
> together the first time you wire it up.

For the richest dashboard, also point the gateway at the free MaxMind databases
(city plus ASN) and, if you want hostnames, turn reverse DNS on. Download
GeoLite2-City and GeoLite2-ASN from MaxMind (free account), drop the `.mmdb`
files on the server, and add:
```ini
Environment=SENTINEL_GEO_DATABASE_PATH=/home/deploy/geo/GeoLite2-City.mmdb
Environment=SENTINEL_ASN_DATABASE_PATH=/home/deploy/geo/GeoLite2-ASN.mmdb
Environment=SENTINEL_REVERSE_DNS_ENABLED=true
```
Without the databases the dashboard still works; it just shows less location
detail (it falls back to an HTTP geo provider for coordinates and skips ASN).

For the dashboard's date-range filters (last 7 days, last 30 days, and so on)
to work across restarts, turn on the connection-history database. It is a
separate SQLite file that stores only connection metadata, never key material,
and old rows are pruned automatically. Add to the KMS service:
```ini
Environment=QCG_TELEMETRY_HISTORY_PATH=/var/lib/qcg/telemetry.db
Environment=QCG_TELEMETRY_HISTORY_RETENTION_DAYS=90
```
Without this the Live Monitor still shows the current, in-memory view; it just
cannot look back over long date ranges after a restart.

Start it:
```bash
sudo systemctl daemon-reload
sudo systemctl enable --now sentinel-gate
sudo systemctl status sentinel-gate
```

### 9.4 Tell the KMS how to reach the gateway (this is what lights up the dashboard)

Edit the KMS service and add two lines so it can pull the live telemetry. Use
the **same token** from step 9.2:
```bash
sudo systemctl edit qcg-kms
```
In the editor add, under `[Service]`:
```ini
[Service]
Environment=QCG_SENTINEL_ADMIN_URL=http://127.0.0.1:8080
Environment=QCG_SENTINEL_ADMIN_TOKEN=PASTE_THE_SAME_TOKEN_FROM_9.2
```
Then reload and restart the KMS:
```bash
sudo systemctl daemon-reload
sudo systemctl restart qcg-kms
```
That is the whole link. The KMS now calls the gateway server-side for the
dashboard data, so the token stays on the server and the browser never talks to
the gateway directly. If you ever leave these two lines out, the dashboard
simply says monitoring is not configured, nothing breaks.

### 9.5 Point Caddy at the gateway instead of the KMS

```bash
sudo nano /etc/caddy/Caddyfile
```
```
kms.yourcompany.com {
    reverse_proxy 127.0.0.1:8080
}
```
```bash
sudo systemctl reload caddy
```
Traffic now flows browser, to Caddy, to Sentinel Gate, to the KMS. Visit the
site again; it behaves exactly the same, now with the protection layer active.

### 9.6 Check it worked

1. Sign in to `https://kms.yourcompany.com` as the admin.
2. The **Live Monitor** panel at the top of the console should show your own
   connection appear within a second or two: a dot on the map, a count, and a
   row in the recent-connections table with your location, network operator, and
   device. If it says monitoring is not configured, recheck that the token in
   step 9.4 matches the one in the gateway service (9.3), and that
   `systemctl status sentinel-gate` is active.

**Device mTLS (optional, advanced):** if you want only company-issued devices to
connect, you run your own small certificate authority, issue a client
certificate per laptop, and enable Sentinel Gate's mTLS
(`SENTINEL_MTLS_ENABLED=true`). This is a larger topic, do it once the basics
are solid.

---

## 10. First run: admin, users, keys

1. Visit `https://kms.yourcompany.com` and **create the admin account**.
2. As employees request accounts (Create account), approve them in **Account
   Requests**, set each person's **role**, and **grant** them the keys they need.
3. For each person/laptop, click **Generate Access Key** and give them that token
   (securely), that's what their `qcg` client uses. (See the Employee guide.)
4. Encourage everyone to enable **two-factor** in the Security panel.

---

## 11. Backups, updates, and keeping it healthy

**Back up two things:**
- The **master key**, offline, in a password manager. Without it the database is
  unreadable. (It's only in the systemd file and your backup, never commit it.)
- The **database** at `/var/lib/qcg/qcg.db`. A simple nightly copy:
  ```bash
  # example: copy with a timestamp (add to a cron job)
  cp /var/lib/qcg/qcg.db ~/backups/qcg-$(date +%F).db
  ```
  Store copies off the server too (download them, or push to object storage).

**See logs / restart:**
```bash
sudo journalctl -u qcg-kms -f          # live KMS logs
sudo journalctl -u sentinel-gate -f    # live gateway logs
sudo systemctl restart qcg-kms
```

**Update to a new build later:** upload the new zip, unzip over a fresh folder,
`pip install -e .` in its venv, point the systemd `WorkingDirectory`/`ExecStart`
at it (or replace files in place), and `sudo systemctl restart qcg-kms`. The
database migrates itself on start.

**Keep the OS patched:**
```bash
sudo apt update && sudo apt -y upgrade
```

---

## 11b. Installing liboqs (the production / benchmark KEM backend)

The KMS ships with two ML-KEM-1024 backends. The default `kyber_py` is pure
Python (portable, no build, but slow). For production speed and for paper-grade
benchmarks, install the native `liboqs` C library and its Python binding. The
server auto-selects liboqs when it is present and verified, falling back to
kyber-py otherwise, so this is safe to add at any time.

```bash
# 1. Build tools and OpenSSL development headers (liboqs needs OpenSSL)
sudo apt update && sudo apt -y install cmake gcc ninja-build git python3-dev libssl-dev

# 2. Build and install the liboqs C library
git clone --depth 1 https://github.com/open-quantum-safe/liboqs
cmake -S liboqs -B liboqs/build -DBUILD_SHARED_LIBS=ON -GNinja
cmake --build liboqs/build --parallel
sudo cmake --install liboqs/build
sudo ldconfig

# 3. Install the Python binding into the KMS venv, and point it at the
#    library we just installed so it does not try to rebuild its own copy.
cd ~/qcg && . .venv/bin/activate
pip install liboqs-python
echo 'export OQS_INSTALL_PATH=/usr/local' >> ~/.bashrc
export OQS_INSTALL_PATH=/usr/local

# 4. Verify the binding loads the installed library
python3 -c "import oqs; print('liboqs OK:', oqs.get_enabled_kem_mechanisms()[:3])"

# 5. Force the backend (optional; 'auto' already prefers liboqs) and restart
#    Add  QCG_KEM_BACKEND=liboqs  to the service environment, then:
sudo systemctl restart qcg-kms
```

Confirm which backend is live:
```bash
curl -s https://qcgkms.cloud/api/about
# -> "kem_backend":"liboqs"  means the native library is in use
```

If `/api/about` still shows `kyber_py`, the binding did not load. Common causes:
the build failed because `libssl-dev` was not installed (the cmake step reports
"Could NOT find OpenSSL"); `ldconfig` was not run after install; or
`OQS_INSTALL_PATH` is not set, so the binding tries to rebuild its own copy. Fix
the relevant step above and restart. The service keeps working on kyber-py
meanwhile. See BENCHMARKING.md for how to compare the
two backends once both are installed.

---

## 12. Production checklist (tick before you trust it)

- [ ] Real `QCG_MASTER_KEY` set, and **backed up offline**.
- [ ] `QCG_DB_PATH` on a persistent disk (`/var/lib/qcg`), and backed up.
- [ ] `QCG_ENVIRONMENT=production`, `QCG_ALLOWED_HOSTS` = your real host.
- [ ] KMS bound to `127.0.0.1` only; firewall allows just 22/80/443.
- [ ] HTTPS working via Caddy (valid certificate in the browser).
- [ ] (Option B) Sentinel Gate in front, `SENTINEL_ENABLE_DEMO_ROUTES=false`,
      `SENTINEL_ENVIRONMENT=production`, trusted hosts/proxies set.
- [ ] `QCG_REQUIRE_CHECKOUT` decided (on = every decryption is leased & audited).
- [ ] Each employee has an account (approved), a role, key grants, an Access Key,
      and MFA enabled.
- [ ] Backups scheduled; you've tested restoring the database once.
