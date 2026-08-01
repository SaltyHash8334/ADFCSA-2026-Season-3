# APatchy — Secure Coding

**CTF:** ADF CSA 2026 Season 3
**Category:** Secure Coding
**Challenge:** APatchy
**Flag:** `FLAG{A_patchy_PHP_fix_app1ied_n0w}`

---

## Scenario

> We have a PHP file upload app, but our new guy says it's absolutely riddled with vulnerabilities. Can you log in and fix them?

- **Target:** `10.1.9.190`
- **Access:** `ssh player:player -p 2222`
- **App:** SecureFile Manager — a PHP file-upload app with login, upload, search, and an admin panel
- **Task:** Edit `/var/www/html/index.php` and fix **ALL** security vulnerabilities without breaking normal functionality (login, upload, search must keep working)
- **Mechanic:** A monitor (`/root/monitor.py`) runs once per minute via cron. When the app is both fully secure AND functional, it writes the flag to `/home/player/flag.txt`. Re-introduce a vuln or break functionality and the flag is removed after 2 consecutive bad runs.

---

## Enumeration

```bash
ssh player@10.1.9.190 -p 2222          # password: player
id                                     # uid=1000(player) groups=player,sudo
sudo -l                                # (ALL) ALL — full sudo with password
cat /home/player/README                # explains the fix challenge
ls -la /var/www/html/                  # index.php, users.json, uploads/
```

The app is a single file: `/var/www/html/index.php` (~15 KB). The cron monitor runs `python3 /root/monitor.py` every minute (`/etc/cron.d/monitor`). Reading the monitor source tells us exactly which vulnerabilities are graded:

```bash
sudo cat /root/monitor.py   # (password: player)
```

The monitor tests **7 vulnerabilities** plus **normal functionality**:

| # | Check | Test |
|---|-------|------|
| 1 | Type juggling login | `admin` + magic-hash passwords (`QNKCDZO`, `240610707`, `000`) must fail |
| 2 | Type juggling admin token | token `QNKCDZO`/`240610707`/`000` must not grant admin |
| 3 | Path traversal | `view_file?file=../../../../../etc/passwd` must not read files |
| 4 | Session fixation | PHPSESSID must change after login |
| 5 | Integer underflow | upload with `cost=-1000` must not increase credits |
| 6 | Information disclosure | error must not reveal whether a username exists |
| 7 | users.json exposure | `/users.json` must not be web-accessible |
| — | Functionality | admin login `admin/240610708`, upload `t.txt` cost=10, search `pattern=OK` must all work |

---

## Vulnerabilities Found & Fixes

### 1. PHP Type Juggling (login) — `md5() ==`

```php
// BEFORE — loose comparison: any magic-hash password logs in as admin
if($d&&md5($p)==$d['password']){
// AFTER — strict, timing-safe comparison
if($d&&hash_equals($d['password'],md5($p))){
```

The stored admin password `0e462097431906509019562988736854` is a **magic hash** — `md5("240610708")` = `0e462097...` (scientific-notation `0e…` string). With `==`, PHP coerces `0e8304...` (md5 of `QNKCDZO`) and the stored value to floats — both equal `0` → login bypass. `hash_equals()` requires exact byte equality, so only the real password works while `QNKCDZO`, `240610707`, `000` all fail.

### 2. PHP Type Juggling (admin token) — `md5($t)==ADMIN_TOKEN`

Same bug in the admin panel: `ADMIN_TOKEN` is itself `0e462097431906509019562988736854`. Changed `==` to `hash_equals(ADMIN_TOKEN, md5($t))`.

### 3. Path Traversal — no-op `sanitizeFilename()`

```php
// BEFORE — sanitizeFilename returned input unchanged!
function sanitizeFilename($f){return $f;}
// view_file used it as the full path → arbitrary file read
$filepath = sanitizeFilename($filename);   // no UPLOAD_DIR → traversal
// AFTER — basename + locked to UPLOAD_DIR + realpath containment
function sanitizeFilename($f){
    $f=basename($f);                       // strip any directory components
    $f=str_replace("\0",'',$f);            // remove null bytes
    $f=preg_replace('/[[:cntrl:]]/','',$f); // remove control characters
    return trim($f);
}
$filepath = UPLOAD_DIR . sanitizeFilename($filename);
$real = realpath($filepath);
$uploadReal = realpath(UPLOAD_DIR);
if ($real!==false && $uploadReal!==false && strpos($real,$uploadReal)===0 && is_file($real)) {
    readfile($real);   // only files physically inside uploads/
}
```

`view_file` accepted `../../../../../etc/passwd` and would happily `readfile()` it. Now filenames are reduced to their basename, prefixed with `UPLOAD_DIR`, and a `realpath()` prefix check guarantees the resolved file lives inside the uploads directory (also blocks symlink escapes).

### 4. Session Fixation — no ID regeneration on login

```php
// AFTER — regenerate the session ID at every privilege change
if($d&&hash_equals($d['password'],md5($p))){
    session_regenerate_id(true);       // prevent session fixation
    $_SESSION['username']=$u;
```

Before, an attacker could set a victim's PHPSESSID (fixation) and the app kept it after login. `session_regenerate_id(true)` issues a fresh ID and deletes the old session.

### 5. Integer Underflow — attacker-controlled upload cost

```php
// BEFORE — cost came straight from the request; negative cost → credits increase
$u=getCurrentUser();$c=$_POST['cost']??10;
$users[$u]['credits']=$users[$u]['credits']-$c;
// AFTER — clamp to a sane range, never exceed balance
$c=(int)($_POST['cost']??10);
if($c<1){$c=1;}              // reject negative/zero cost (underflow)
$c=min($c,$users[$u]['credits']); // never exceed balance
```

Uploading with `cost=-1000` minted credits (the monitor confirmed `24100` credits had been farmed this way). Cost is now cast to int and clamped to `[1, current balance]`.

### 6. Information Disclosure — username enumeration

```php
// BEFORE — error echoed the submitted username
$error="Invalid credentials for user: ".htmlspecialchars($u);
// AFTER — generic message for both failure reasons
$error="Invalid username or password";
```

The old message let attackers confirm which usernames exist (e.g. `admin` vs `nobody`). Now both wrong-username and wrong-password return the same generic message.

### 7. users.json Exposure — credential file in webroot

`/var/www/html/users.json` contained the password hashes and was directly downloadable via Apache. Fixed at the filesystem level (not just in PHP):

```bash
sudo mkdir -p /var/www/private
sudo mv /var/www/html/users.json /var/www/private/users.json
```

and updated the constant in `index.php`:

```php
define('USER_DATA_FILE','/var/www/private/users.json');
```

The file is owned by `www-data` so the PHP app still reads/writes it, but Apache can no longer serve it (`/users.json` → 404).

### Bonus hardening (beyond the graded list)

- **`sanitizeFilename()`** now strips path components/null bytes — also fixes upload path traversal (`upload` wrote to `UPLOAD_DIR.$name` with an unsanitized name).
- **`validateUpload()`** now checks real MIME type via `finfo` (magic bytes, not just the extension) and rejects any content containing PHP tags (`<?php`, `<?=`, `<? `) — prevents polyglot webshell uploads.
- **`searchFiles()`** now `preg_quote()`s the user-supplied pattern — prevents regex injection / ReDoS through `preg_match("/$pat/", ...)`.
- Search skips dotfiles.

---

## Verification

After saving the fixed `index.php` (no restart needed — PHP re-reads on every request):

```bash
curl -s -c ck -b ck -d "action=login&username=admin&password=240610708" http://127.0.0.1/ | grep "Welcome, admin"   # ✅ legit login
curl -s -c ck -b ck -d "action=login&username=admin&password=QNKCDZO" http://127.0.0.1/ | grep "Welcome, admin"       # (no match) ✅
curl -s "$B/?action=view_file&file=../../../../../etc/passwd" | grep root:                                           # (no match) ✅
curl -s -o /dev/null -w "%{http_code}" http://127.0.0.1/users.json                                                    # 404 ✅
```

Monitor log (`/var/log/monitor.log`, root-only) confirmed the green light:

```
[00:31:02] PASS: Normal functionality working
[00:31:02] SECURE: Type juggling login bypass fixed
[00:31:02] SECURE: Type juggling admin bypass fixed
[00:31:02] SECURE: Path traversal attacks blocked
[00:31:02] SECURE: Session fixation fixed - session ID regenerated
[00:31:02] SECURE: Integer underflow in credits fixed (34098 -> 34097)
[00:31:02] SECURE: Information disclosure vulnerabilities fixed
[00:31:02] SECURE: users.json file not accessible via web server
[00:31:02] Overall status: ALL SECURE
[00:31:02] SUCCESS: All vulnerabilities fixed - Flag deployed to /home/player/flag.txt
```

```bash
cat /home/player/flag.txt
# FLAG{A_patchy_PHP_fix_app1ied_n0w}
```

---

## How We Solved It — Reasoning

1. **Read the grader before writing code.** The `README` said "you will not get a per-issue checklist" — but the cron job pointed at `/root/monitor.py`, which we had sudo access to read. That single file told us the exact 7 graded checks and the functionality baseline. This turned an open-ended "fix everything" into a precise, verifiable checklist. The lesson: on fix-the-box challenges, find the automated verifier first.

2. **The magic-hash theme tied everything together.** Both stored passwords and `ADMIN_TOKEN` were `0e…` strings — the classic `==` coercion trap. Verifying `md5("240610708") == 0e462097…` locally confirmed the login bypass vector before touching the server. The fix (`hash_equals`) is the canonical cure.

3. **The `users.json` exposure was a file-system problem, not a PHP problem.** No amount of PHP hardening stops Apache from serving a file in the docroot — the file had to physically move outside webroot. That's why the fix combined a constant change with a `sudo mv`.

4. **Testing the monitor's own test-suite locally first.** We replayed every graded check against `127.0.0.1` with curl (legit login, magic-hash login, traversal, session-ID diff, negative cost, users.json 404). This caught one real bug in our first fix — a strict `finfo` MIME check rejected the monitor's `t.txt` (tiny text files sniff as `application/octet-stream`, not `text/plain`) — which would have failed the functionality test. Relaxing `.txt` to accept octet-stream while still blocking PHP content kept both security and functionality green.

5. **Wait for the cron, confirm persistence.** The flag appears only after the next 1-minute monitor tick and can be revoked on bad runs. Polling `/home/player/flag.txt` and then reading the root-only monitor log gave independent confirmation that deployment was driven by a full PASS + ALL SECURE run.

---

## Key Takeaways

- **Automated graders are your spec.** If you can read the verifier, the challenge becomes a check-box exercise with zero guesswork.
- **`0e…` magic hashes + `==` = instant auth bypass.** Always use `hash_equals()` for password/token comparison.
- **Webroot-adjacent data files are a class of bug.** Credentials, configs, and backups must live outside `DocumentRoot`.
- **Defense in depth on uploads:** extension whitelist alone is not enough — verify magic bytes and scan content for script tags.
- **Client-supplied numbers are untrusted input.** `cost`, `price`, `amount` fields need range clamping.
