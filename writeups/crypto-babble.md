# CryptoBabble — ADF CSA 2026 Season 3

**Category:** Cryptanalysis  
**Flag:** `FLAG{CAB}`

---

## 1. Challenge Material

The challenge supplied a single text file:

```text
....germianting hyperbolical squelching undulations

wabbling bamboozle! germinating orbish blinkoggles solemnly..    
```

The conspicuous punctuation is structural:

- a blank line follows word 4;
- `!` follows word 6;
- the three resulting word groups therefore have sizes **4 / 2 / 4**.

---

## 2. Layer One — Initial-Letter Caesar Cipher

Tokenising the text gives these ten word initials:

```text
G H S U | W B | G O B S
```

A Caesar shift of +12 gives:

```text
S T E G | I N | S A N E
```

or:

```text
STEG | IN | SANE
```

This is an instruction: there is steganography in the sane-looking cover words. It is not the final flag.

---

## 3. Layer Two — Consonant-Parity Morse

The same punctuation groups are Morse-letter boundaries. Count consonants in each word and map:

- **odd** number of consonants → `-`
- **even** number of consonants → `.`

| Group | Words | Consonant counts | Morse | Decoded letter |
|---|---|---:|---|---|
| 1 | `germianting hyperbolical squelching undulations` | 7, 8, 7, 6 | `-.-.` | `C` |
| 2 | `wabbling bamboozle` | 6, 5 | `.-` | `A` |
| 3 | `germinating orbish blinkoggles solemnly` | 7, 4, 8, 6 | `-...` | `B` |

The payload is therefore:

```text
CAB
```

---

## 4. How We Solved It — Reasoning

### Initial Observations

The words are deliberately gibberish, but the punctuation is unusually placed: four words before a blank line, two before an exclamation mark, and four after it. Treating punctuation only as decoration would discard the strongest structural signal in the file.

### Key Discoveries

1. **Initials form a clean Caesar ciphertext.** The initials `GHSUWBGOBS` shift by +12 to `STEGINSANE`.
2. **Punctuation resolves the intended spacing.** Applying the file's 4 / 2 / 4 segmentation produces `STEG | IN | SANE`, so the first layer is a steganographic instruction rather than a final flag value.
3. **The same groups fit Morse letter lengths.** Four, two, and four symbols are natural Morse group sizes. Testing simple per-word binary features found consonant parity to give valid Morse in all three groups.
4. **Only one polarity yields coherent output.** Odd-consonant words as dashes and even-consonant words as dots decode deterministically to `C`, `A`, and `B`.

### Rejected Hypotheses

- **`FLAG{STEGINSANE}` and separator/case variants:** rejected because `STEG IN SANE` is a layer-one instruction.
- **Further fixed-character Caesar columns:** letters 2 through 12 of every word do not form readable Caesar plaintext.
- **Whitespace-only encoding:** the four trailing spaces cannot carry a complete flag payload by themselves.

### Key Insight

Both layers use the punctuation delimiters. In the first layer they expose the instruction `STEG | IN | SANE`; in the second they define Morse boundaries. Correlating those two independent observations avoids mistaking an intermediate plaintext for the flag.

---

## 5. Flag

```text
FLAG{CAB}
```
