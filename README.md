# Phishing Link Detector

A Chrome extension (Manifest V3) that scores every link you hover over and shows a floating verdict card next to the cursor: where the link *really* goes, a 1–100 safety score, and the reasons behind it.

No network requests, no accounts, no data collection. Scoring happens entirely inside the extension's service worker.

![Verdict card states: green "Looks safe", amber "Use caution", red "Suspicious link", grey "Shortened link"](docs/states.svg)

## Install (load unpacked)

1. Clone or download this repository.
2. Open Chrome and go to `chrome://extensions`.
3. Turn on **Developer mode** (toggle in the top-right corner).
4. Click **Load unpacked** and select the `phishing-detector-extension` folder (the one containing `manifest.json`).
5. Open any web page and rest the cursor on a link for about half a second.

After editing any file, click the reload icon on the extension's card in `chrome://extensions` and refresh the page.

## What the card shows

| Colour | Status | Score |
| --- | --- | --- |
| Green | Looks safe | 75 – 100 |
| Amber | Use caution | 50 – 74 |
| Red | Suspicious link | 1 – 49 |
| Grey | Shortened link | – (bit.ly, t.co, … hide their destination, so no score is given) |

Below the status line the card prints the **registrable domain** the link leads to — `account-services.net` for `https://paypal.com.account-services.net/login` — followed by up to three reasons and any redirectors that were unwrapped.

## How scoring works

Links wrapped by a known redirector (Google search/Docs/Gmail `google.com/url?q=`, Microsoft Safe Links, Facebook, YouTube, Slack, Reddit, Tumblr, Barracuda, Proofpoint) are unwrapped first, so the destination gets scored instead of the wrapper.

The hostname is then split against a public-suffix list, so `accounts.google.com` is judged as `google.com`, `shop.example.co.uk` as `example.co.uk`, and `evil.github.io` as `evil.github.io`. Every URL starts at **100** and loses points for each rule that fires:

| Rule | Example | Penalty |
| --- | --- | --- |
| Look-alike of a known brand: typos, digits, letter pairs or foreign letters standing in for the real spelling | `amaz0n.com`, `rnicrosoft.com`, `googel.com`, `xn--80ak6aa92e.com` (Cyrillic "аррӏе") | −60 |
| A domain before `@` — the real site is what follows it | `https://google.com@evil.com/` | −60 |
| Hostname is a raw IP address (v4 or v6) | `http://192.168.1.10/login` | −60 |
| Uses a known brand's name on a domain the brand does not own | `paypal.com.evil.net`, `secure-paypal.com`, `paypal-verify.blogspot.com` | −50 |
| TLD that is heavily abused for phishing | `.xyz`, `.top`, `.tk`, `.click`, `.icu`, … | −40 |
| `login`, `signin`, `secure`, `verify`, `account`, `update`, `password` or `webmail` in the registrable domain | `secure-login.com` | −30 |
| Embedded username/password | `https://admin:hunter2@example.com/` | −30 |
| `http://` instead of `https://` | | −20 |
| More than two hyphens in the hostname | `my-bank-secure-login.xyz` | −20 |
| Hostname longer than 40 characters | | −15 |
| Internationalised (punycode) label | `xn--mller-kva.de` | −15 |
| One of the keywords above in a subdomain only | `accounts.google.com` | −10 |

The result is clamped to 1–100. Brand rules skip the brand's own domains (`paypalobjects.com`, `itunes.apple.com`, `outlook.office.com`) and subdomains of large community platforms (`apple.stackexchange.com`). Around 80 frequently impersonated brands are covered; see `BRANDS` in [lists.js](lists.js).

## Files

| File | Purpose |
| --- | --- |
| `manifest.json` | MV3 manifest: registers the module service worker and the content script + stylesheet |
| `content.js` | Delegated hover handling on `<a>` tags, 400 ms debounce, verdict card rendering |
| `styles.css` | Card styling with `.safe` / `.caution` / `.warning` / `.unknown` variants |
| `background.js` | Service worker: answers `ANALYZE_URL` messages using the engine |
| `scoring.js` | The rules and `analyzeUrl()` |
| `lookalike.js` | Punycode decoding, confusable-letter folding, homoglyph and typo matching |
| `redirects.js` | Redirector unwrapping |
| `lists.js` | Data: public suffixes, brands, keywords, abused TLDs, shorteners |
| `test/` | `node --test` suite (no dependencies) |

## Development

```bash
npm test
```

Requires Node 20 or newer; the suite runs on every push via GitHub Actions. The engine is plain ES modules with no `chrome.*` dependencies, so new rules can be developed and tested entirely in Node.

## Limitations

This is a heuristic, not a blocklist or a reputation service. It knows nothing about a site's history, only about how its address is shaped. A carefully chosen domain with no tell-tale features will score high, and an unusual but honest address (a raw IP on your intranet, a brand name in a fan site's subdomain) will score low. Treat the card as a hint, not a verdict.

## License

[MIT](LICENSE)
