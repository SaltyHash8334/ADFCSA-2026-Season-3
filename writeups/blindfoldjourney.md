# BlindfoldJourney — Geo-Intelligence

**CTF:** ADF CSA 2026 Season 3
**Category:** Geo-Intelligence
**Challenge:** BlindfoldJourney
**Flag:** `FLAG{THESUS}`

---

## Scenario

> On a whimsical adventure, I blindfoldedly hitchhiked around the world, collecting memories. Oops! Now, I've accidentally mixed up my travel photos with ones from a different journey, and they're stored in a peculiar folder structure. Can you unravel the mystery of these destinations?

- **Files:** `4_hitchhiking/` — 13 numbered folders (`1`–`13`), each containing a single photo (`0.jpg` / `0.png`)

---

## Step 1 — Recognising the "peculiar folder structure"

The archive layout is odd in two ways:

1. **Every file is named `0.<ext>`** — no descriptive names, only the folder number identifies each photo.
2. **Some `.png` files are not PNGs.** Checking magic bytes:

```
1/0.png  →  FF D8 FF E0 (JPEG)   ← mislabelled
3/0.png  →  FF D8 FF E0 (JPEG)   ← mislabelled
4/0.png  →  FF D8 FF E0 (JPEG)   ← mislabelled
8/0.png  →  89 50 4E 47 (real PNG)
11/0.png →  89 50 4E 47 (real PNG)
12/0.png →  89 50 4E 47 (real PNG)
```

Exactly **three files carry a wrong extension** — the "mixed up" photos from the description. No EXIF/GPS, no trailing data, no steganographic payloads — the photos themselves are clean.

## Step 2 — Identifying the 13 destinations

Each photo is a street-level scene of a real city. Identification combined **local CLIP/OCR analysis** (no GPU in the VM, so a CPU-only CLIP ensemble + EasyOCR) with **free vision-LLM passes** (Gemma-4-26B / Nemotron VL via OpenRouter) and **cross-checks against Wikimedia Commons / OpenStreetMap**:

| # | Destination | Key evidence |
|---|-------------|--------------|
| 1 | Bangkok, Thailand | Thai street, "99 Care" shopfront, model consensus |
| 2 | Stockholm, Sweden | Skeppsbron waterfront / Royal Dramatic Theatre |
| 3 | Barcelona, Spain | La Rambla; **"MSF España – www.msf.es"** sign read by OCR |
| 4 | Philadelphia, USA | ONE WAY sign, brick row houses, blue trash bins |
| 5 | Brisbane, Australia | KEEP LEFT sign, subtropical street |
| 6 | Alexandria, Egypt | Waterfront; "ALEXANDRIA" text on banners |
| 7 | Buenos Aires, Argentina | Samsung "Sin bordes, sin límites" tower; **no mountains** → rules out Santiago/Mexico City |
| 8 | Brussels, Belgium | Bilingual "Salon Lavoir – Wassalon" + Electrolux sign; CLIP match Brussels ≫ Hamburg |
| 9 | Stockholm, Sweden | Östermalms Saluhall market hall ("GOTT" = Swedish for "good"); CLIP match 0.80 |
| 10 | Tallinn, Estonia | **"Pirosmani"** Georgian-restaurant banner; matches Wikimedia photo of Pirosmani, Tallinn |
| 11 | Hoorn, Netherlands | "Mecklenburgstraat" street sign; CLIP match 0.81 to Wikimedia "Mecklenburgstraat, Hoorn" |
| 12 | Accra, Ghana | White perimeter wall, brown-brick apartment blocks |
| 13 | Helsinki, Finland | Red **Prisma** supermarket sign (Finnish chain), EU plates, Nordic pines |

## Step 3 — The flag: the mix-up spells the answer

The description says the travel photos were **"mixed up"** with ones from a different journey. The only genuinely mixed-up items in the structure are the **three files with wrong extensions** — folders `1`, `3` and `4`:

| Folder | Destination | ISO 3166-1 code |
|--------|-------------|-----------------|
| 1 | Bangkok, **Thailand** | **TH** |
| 3 | Barcelona, **Spain** | **ES** |
| 4 | Philadelphia, **USA** | **US** |

Concatenating the country codes of the mixed-up photos:

```
TH + ES + US  =  THESUS
```

Six letters — exactly matching the stated `FLAG{ABCDEF}` format. (The nod to "Theseus" is fitting: a blindfolded hitchhiker who can't tell which journey each photo belongs to is living the Ship-of-Theseus identity paradox.)

```
FLAG{THESUS}
```

---

## Takeaways

- **Always check magic bytes, not extensions** — the mislabelled files were the payload, not an accident.
- **Triangulate weak vision models**: no single model identified all 13 reliably; combining CLIP similarity, OCR text extraction, and two vision LLMs converged on the same set.
- **Wikimedia Commons + OpenStreetMap are free ground-truth databases** — a street name (Mecklenburgstraat) or restaurant (Pirosmani) can be geolocated and photo-matched directly.
