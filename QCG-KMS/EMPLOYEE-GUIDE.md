# Using the QCG Client (the `qcg` tool): Complete Employee Guide

This explains, in plain words, exactly how a staff member uses Quantum Cloud Guard
on their own computer: where the program comes from, how to install it, how to set
it up, and the full day-to-day workflow of locking and unlocking files. There's a
short section for the administrator first (how to produce and hand out the
program), then the employee section.

---

## Part A (for the administrator): where the `.exe` comes from

There is **no public download** of the client, and it is **not inside the server
zip as a ready-made `.exe`**. That's deliberate: the program is built per operating
system, and you hand it to your own people. You build it once and distribute it.

**Why it isn't pre-made:** the tool is packaged with PyInstaller, which can only
build an executable for the operating system it runs on (a Windows machine builds
`qcg.exe`, a Mac builds the Mac version, Linux builds the Linux one). So the build
happens on your side.

You have two ways to produce it.

### Option 1: Build it yourself on a Windows PC
On any Windows machine with Python installed, from the project folder:
```bash
pip install pyinstaller cryptography
pyinstaller --onefile --name qcg --clean --noconfirm --collect-submodules cryptography packaging/qcg_entry.py
```
The result appears at `dist\qcg.exe`. That single file **is** the client. (On a
Mac or Linux box the same command produces `dist/qcg`.)

### Option 2: Let GitHub build all three for you (no Windows box needed)
The project ships a ready CI workflow at `.github/workflows/build-cli.yml`. Push
your code to a GitHub repo, then either push a version tag or click "Run workflow"
on the Actions tab. It builds on Windows, macOS, and Linux and gives you three
downloadable artifacts:
- `qcg-windows` → contains `qcg.exe`
- `qcg-macos` → contains `qcg`
- `qcg-linux` → contains `qcg`

Download the right one for each employee.

### Handing it out
Give each employee three things, over a trusted channel (company chat, signed
email, internal share):
1. The **program file** for their OS (`qcg.exe` for Windows users).
2. The **server address**, e.g. `https://kms.yourcompany.com`.
3. Their personal **API key** (the `qcg_...` token you create with **Generate Access Key**
   on their row in the Employees panel). Treat it like a password, one per
   person/laptop, and you can revoke it any time.

**Honest note:** shipping an `.exe` is about convenience and stopping casual
tampering, it is **not** a secret. The security doesn't depend on hiding the
client; the private key stays on the server and the client only ever handles a
short-lived data key it needs anyway. (The AWS CLI is fully open for the same
reason.) So distribute it freely to staff; just don't treat the file itself as a
secret or a security control.

---

## Part B: For the employee

### B1. First, get an account

Before the tool is useful, you need an approved account on the company KMS.

1. Open the server address your admin gave you (e.g.
   `https://kms.yourcompany.com`) in a browser.
2. Click **Create account**, choose a username and password, and submit.
3. You'll see a message that your request was received. **You can't sign in yet**
  , an administrator has to approve you first. Once they do, you can sign in.
4. (Recommended) After signing in, open the **Security** panel and turn on
   **two-factor authentication**: scan the QR code with an authenticator app
   (Google Authenticator, Authy, 1Password, etc.). After that, signing in also
   asks for a 6-digit code.

If you ever forget your password, click **Forgot password?** on the sign-in
screen. The admin will issue you a one-time temporary password; when you sign in
with it, the site immediately asks you to set a new password.

### B2. Install the program

You'll receive a single file. **No Python or installer is required**, it's
self-contained.

**Windows (`qcg.exe`):**
1. Save `qcg.exe` somewhere permanent, e.g. `C:\Users\<you>\qcg\qcg.exe`.
2. The first time you run it, Windows SmartScreen may warn that it's from an
   unknown publisher (normal for in-house tools). Click **More info → Run anyway**.
   (Your admin can sign the executable to avoid this.)
3. To run it from any folder by just typing `qcg`, add its folder to your PATH:
   - Press Start, type "environment variables", open **Edit the system
     environment variables → Environment Variables**.
   - Under **User variables**, select **Path → Edit → New**, add
     `C:\Users\<you>\qcg`, and click OK.
   - Open a **new** PowerShell/Command Prompt window so the change takes effect.
   - (If you skip this, just run it by full path, e.g. `C:\Users\<you>\qcg\qcg.exe ...`.)

**macOS (`qcg`):**
1. Save the file, then make it runnable: open Terminal and run
   `chmod +x ~/Downloads/qcg`.
2. The first run may be blocked by Gatekeeper ("unidentified developer"). Allow it
   in **System Settings → Privacy & Security → Open Anyway**, or run
   `xattr -d com.apple.quarantine ~/Downloads/qcg` once.
3. Optionally move it onto your PATH: `sudo mv ~/Downloads/qcg /usr/local/bin/qcg`.

**Linux (`qcg`):**
1. `chmod +x ~/Downloads/qcg`
2. Optionally `sudo mv ~/Downloads/qcg /usr/local/bin/qcg` so you can type `qcg`
   anywhere.

Check it works:
```bash
qcg --help
```
(Windows without PATH: `C:\Users\<you>\qcg\qcg.exe --help`.) You should see the
list of commands.

### B3. Tell the tool where the server is (one-time setup)

The client needs your **server URL** and your **API key**. You can provide them in
any of three ways, pick one.

**Easiest (set once, remembered): a config file.**
Create a file at `~/.qcg/config.json` (on Windows that's
`C:\Users\<you>\.qcg\config.json`) containing:
```json
{ "url": "https://kms.yourcompany.com", "api_key": "qcg_your_token_here" }
```
After this, you never have to pass them again.

**Or environment variables** (good for scripts):
```bash
export QCG_KMS_URL=https://kms.yourcompany.com
export QCG_KMS_API_KEY=qcg_your_token_here
```
(On Windows PowerShell: `$env:QCG_KMS_URL="https://kms.yourcompany.com"` and
`$env:QCG_KMS_API_KEY="qcg_your_token_here"`.)

**Or pass them on each command** with `--url` and `--api-key`.

The examples below assume you've set the config file or environment variables, so
the commands stay short.

---

### B4. The everyday workflow

There are exactly **three commands**: lock a file, unlock a file, and return a
file after you've edited it. Here's the full story with a real example, protecting
a database backup called `backup.sql`.

#### Lock a file (encrypt): e.g. before uploading to the cloud
```bash
qcg encrypt backup.sql --key prod-db
```
- `prod-db` is the name of the key your admin granted you.
- This creates `backup.sql.qcg`, the locked version. The original is left in
  place; you upload the `.qcg` file to wherever you keep it (cloud storage, etc.).
- The locked file is useless to anyone without the server: the file's contents are
  encrypted, and the key needed to open it is itself wrapped by the server's
  post-quantum key.
- To choose the output name: `qcg encrypt backup.sql --key prod-db -o backup.enc`.

#### Unlock a file (decrypt): e.g. after downloading it again
```bash
qcg decrypt backup.sql.qcg
```
- This produces `backup.sql` (the readable file).
- Importantly, decrypting **starts a time-limited "checkout."** Think of it like
  borrowing the file from the vault: the server records that *you* opened it, for
  *how long* you're allowed (your role decides, e.g. an hour), and writes it in
  the audit log. The admin can see this live.
- The tool drops a small companion file next to your file called
  `backup.sql.qcglease`, that's just the borrowing receipt; leave it there until
  you return the file.
- It prints your deadline. If you hold the file past it without returning it, the
  system records a timeout and can alert an administrator. (This is an
  accountability signal, not a lock, see the honest note at the end.)
- If your admin has turned on "require checkout," this is the only way you can
  decrypt; a plain unwrap is refused. (Admins have a `--no-checkout` break-glass
  option; regular staff don't need it.)

#### Return a file (check-in): after you've edited it
```bash
qcg checkin backup.sql --key prod-db
```
- This re-locks your edited file into a fresh `backup.sql.qcg`, **closes the
  checkout** (the borrowing receipt is settled), and then **shreds the local
  readable copy** so a plaintext file isn't left lying around. Upload the new
  `.qcg`.
- It finds the lease automatically from the `.qcglease` receipt. If you want to
  keep the readable file after returning it, add `--keep-plaintext`.

That's the whole loop: **encrypt → upload → (later) download → decrypt → edit →
checkin → upload**. The server never sees your file's contents at any point, only
the small wrapped key.

#### Check a file without unlocking it
```bash
qcg info backup.sql.qcg
```
- Shows the file's original name, which key and version it uses, the algorithm,
  and which KEM backend encrypted it. It does not decrypt anything and does not
  start a checkout, so it is always safe to run.

#### Quick reference
```bash
qcg encrypt <file> --key <keyname> [-o <out>]      # lock a file
qcg decrypt <file.qcg> [-o <out>] [--no-checkout]  # unlock (starts a checkout)
qcg checkin <file> --key <keyname> [--keep-plaintext]   # re-lock, close checkout, shred
qcg info <file.qcg>                                # show a file's details (no unlock)
```
If you didn't set config/env, prefix any command with
`--url https://kms.yourcompany.com --api-key qcg_...`.

---

### B5. What the files mean

- `something.qcg`, the **locked** version. Safe to store/upload anywhere.
- `something` (no extension change), the **unlocked**, readable version. Keep it
  only while you're working; `checkin` removes it for you.
- `something.qcglease`, a tiny **receipt** for an open checkout. The tool uses it
  to know which checkout to close on `checkin`. Don't delete it manually.

---

### B6. If something goes wrong

- **"KMS url and api key required"**: you didn't set the config file/env, or there's
  a typo. Re-check `~/.qcg/config.json` or your environment variables.
- **"not authorized for this key" (403)**: your admin hasn't granted you that key
  yet. Ask them to grant you `prod-db` (or whichever) in the Employees panel.
- **"valid one-time code required"**: you have two-factor on; the website prompts
  for the 6-digit code at sign-in. (The CLI uses your API key, not a code.)
- **"you must set a new password before continuing" (403)**: you logged in with a
  temporary password; finish setting a new password on the website first.
- **Windows won't run it / SmartScreen**: choose **More info → Run anyway**, or
  ask your admin for a signed copy.
- **Lost or leaked API key**: tell your admin; they delete that Access Key and
  issue a new one. Your old token stops working immediately.

---

### B7. One honest thing to understand

Once you're allowed to unlock a file, you can read it, and nothing can stop you
from copying what you read. What this system guarantees is different and still very
valuable: only the **right people**, signed in and approved, can unlock a file, for
a **limited time**, with a **complete, tamper-evident record** of every unlock, and
an **alert** if someone holds a file too long. It protects strongly against the
cloud being breached and against outsiders; for trusted insiders it provides
accountability and deterrence, not an impossible guarantee. Use it accordingly.
