# PhishGuard: A Rule-Based Phishing Link Checker

PhishGuard checks the **text of a web link** and tells you how risky it looks (**Low, Medium or High**), with the reasons in plain sentences. It never opens or visits the link, so checking a dangerous link is safe.

It was built as a BCA project at Chhatrapati Shahu Ji Maharaj University, Kanpur.

> **PhishGuard is a learning and warning tool.** A *Low* result does not prove that a link is safe.

## Why this project

- Fake links often look almost the same as real ones (`paypa1.com` instead of `paypal.com`).
- Blocklists warn only after a fake site has been found, and they usually just say "unsafe".
- PhishGuard works on the link alone, gives a clear rating and **explains why**.

## Features

- 11 separate checks, each looking for one warning sign
- A score, a risk level and plain-language reasons for every link
- Command-line tool and a small Flask web page
- Web page keeps a history of checked links (SQLite) with a **Clear History** button
- 36 automatic tests (pytest)
- An evaluation script that reports recall, precision and false alarms

## How it works

1. You paste a link.
2. PhishGuard runs 11 checks on the link text. Each warning sign adds points.
3. The total score becomes a level.
4. You see the score, the level and the reasons.

| Score | Level |
|---|---|
| 0 – 1 | Low |
| 2 – 3 | Medium |
| 4 or more | High |

### The 11 checks

| # | Check | What it looks for | Points |
|---|---|---|---|
| 1 | Long link | Longer than 75 characters | 1 |
| 2 | IP address | A number instead of a website name | 3 |
| 3 | `@` symbol | `@` in the website part (the browser ignores what comes before it) | 3 |
| 4 | Many subdomains | More than three dots in the website name | 2 |
| 5 | No HTTPS | Link does not start with `https://` | 1 |
| 6 | Suspicious words | login, verify, update, secure, account, signin, confirm, banking | 1 |
| 7 | Brand look-alike | Imitates a known brand (for example `paypa1.com`) without being its real site | 3 |
| 8 | Hyphens or digits | Many hyphens or digits in the website name | 1 |
| 9 | Link shortener | Services such as bit.ly that hide the real address | 2 |
| 10 | Free hosting | Free site builders such as github.io or netlify.app | 2 |
| 11 | Risky ending | Cheap endings: `.xyz`, `.top`, `.click`, `.icu`, `.buzz`, `.cfd` | 1 |

**Example:** `http://secure-login@192.168.1.1/bank.com` scores 3 (`@`) + 3 (IP address) + 1 (no HTTPS) + 1 (words "secure", "login") = **8, High**.

## Screenshots

| Low | Medium | High |
|---|---|---|
| ![Low](screenshots/low.png) | ![Medium](screenshots/medium.png) | ![High](screenshots/high.png) |

## Results

Tested on 62 safe links and three samples of 50 real reported phishing links (from the OpenPhish feed). A link rated **Medium or higher** counts as flagged.

| Sample | How it was used | Phishing caught | Precision | Safe links wrongly flagged |
|---|---|---|---|---|
| A | Used while building the rules | 33 of 50 (66%) | 94.3% | 2 of 62 |
| B | Used to fix the final settings | 44 of 50 (88%) | 95.7% | 2 of 62 |
| Sealed set | Drawn last, tested **once** after the rules were frozen (commit `d1af09d`) | **43 of 50 (86%)** | 95.6% | 2 of 62 |

On the sealed set the accuracy was 92.0% and the false alarm rate 3.2%. If only **High** counted as flagged, it would catch just 16 of 50 (32%), so Medium is counted.

An earlier third sample is not used as evidence, because rules were changed after it was drawn. Each sample has only 50 links, so these numbers are a rough guide, not a guarantee.

### What it gets wrong

- The 2 false alarms are genuine developer pages on `github.io`. Free hosting is a warning sign, but not every free page is fake.
- Missed links mostly use a shortener, a free host or a domain ending that is not yet on the lists, or have no warning sign in the link text at all.

## Installation (Windows)

You need Python 3.12.

```powershell
git clone https://github.com/Pawani-7/Phishguard.git
cd Phishguard
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
```

## Usage

**Web page**

```powershell
python app.py
```

Open the address shown in the terminal (usually http://127.0.0.1:5000), paste a link and press the check button. Results are saved in the history list, which can be cleared.

**Command line**

```powershell
python run_cli.py
```

**Tests**

```powershell
pytest -q
```

**Evaluation**

```powershell
python evaluate.py                          # default phishing sample + safe links
python evaluate.py data\your_phishing_file.txt
```

The phishing test lists are **not included** in this repository. To repeat the evaluation, download reported links from <https://openphish.com> and save them as plain text, one link per line, in the `data` folder. The links are only read as text and are never opened.

## Project structure

```
Phishguard/
├── app.py            Flask web page and history (SQLite)
├── checks.py         The 11 link checks
├── scoring.py        Adds points, picks the level, writes the reasons
├── run_cli.py        Command-line tool
├── evaluate.py       Measures recall, precision and false alarms
├── test_checks.py    Tests for the checks
├── test_scoring.py   Tests for scoring and levels
├── data/             Safe links (phishing test lists are kept private)
├── screenshots/      Images used in this README
└── requirements.txt
```

## Privacy and safety

- Links are analysed as text only and are never opened.
- The history stays in a SQLite file on your own computer.
- Phishing test lists are kept out of this repository.

## Limitations

- It reads only the link text, so a harmful page on a normal-looking address can pass.
- Word, brand, shortener and ending lists are written by hand and are limited.
- Free hosting can flag genuine pages.
- Samples are small (50 links each).

## Future work

- Longer lists of shorteners, free hosts and risky endings
- A larger brand list, including Indian banks and UPI apps
- A check for look-alike letters in domain names (punycode)
- Larger test samples and a browser extension

## Acknowledgements

- Test data: [OpenPhish](https://openphish.com) community feed
- AI assistance: the Clear History feature of the web page was written with help from ChatGPT. I reviewed and tested it, and I can explain how it works.
