# CryptoBabble — ADF CSA 2026 Season 3

**Category:** Cryptanalysis  
**Derived flag:** `FLAG{CUREIS}`

---

## Challenge material

The supplied file contains one structured line of babble-like words:

```text
....germianting hyperbolical squelching undulations

wabbling bamboozle! germinating orbish blinkoggles solemnly..
```

The non-word-looking carrier text, the four leading dots, the blank line, and the exclamation mark are all deliberate structure.

---

## Layer 1 — Read the initials

Taking the first character of each of the ten words produces:

```text
G H S U | W B | G O B S
```

A Caesar `ROT+12` produces:

```text
S T E G | I N | S A N E
```

The blank line and `!` preserve the intended parsing:

```text
STEG | IN | SANE
```

This is an instruction, not a flag: hide/extract the next layer from the *sane* (correct English) carrier words.

---

## Layer 2 — Sane-word second letters

The deliberately malformed/non-word cover strings are:

```text
germianting, wabbling, orbish, blinkoggles
```

The remaining six ordinary English words are:

```text
hyperbolical | squelching | undulations | bamboozle | germinating | solemnly
```

Following the “second letter” route gives:

```text
Y Q N A E O
```

The four literal dots at the beginning of the file supply the Caesar distance, `ROT+4`:

```text
YQNAEO  -- ROT+4 -->  CUREIS
```

Therefore the final payload is:

```text
FLAG{CUREIS}
```

---

## How We Solved It — Reasoning

### Initial observations

The word initials were the most compact channel: ten letters fit a short Caesar instruction, while the unusual `4 / 2 / 4` punctuation grouping suggested that the spacing was meaningful. Trying Caesar shifts on the initials made `ROT+12` stand out immediately as the only clean plaintext, `STEG IN SANE`.

### Evidence correlation

`SANE` has a concrete and testable meaning in the supplied text. Four strings are visibly malformed or invented (`germianting`, `wabbling`, `orbish`, and `blinkoggles`), while the other six are normal English words. Keeping those six words and moving from the already-consumed first character to their second characters yields `YQNAEO`.

The file begins with exactly four dots. Using that literal count as the next Caesar distance gives `CUREIS`, a clean payload. The extraction is reproducible by `solve_cryptobabble.py`, which asserts the source word order, first-layer instruction, four-dot shift, second-letter stream, and final flag.

### Rejected false path

A punctuation-grouped consonant-parity Morse reading can coincidentally spell `CAB`. It is not the intended result: `FLAG{CAB}` was validator-rejected, it does not use the explicit `STEG IN SANE` instruction, and it leaves the leading-dot count unexplained. The sane-word/null-cipher route explains every salient clue and produces the readable payload.

---

## Reproduction

```bash
python3 solve_cryptobabble.py
```

Expected final line:

```text
flag: FLAG{CUREIS}
```
