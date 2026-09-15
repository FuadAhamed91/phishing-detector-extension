# Phishing Link Detector

A Chrome extension (Manifest V3) that scores every link you hover over and shows a floating safety badge next to the cursor: **green** for links that look fine, **red** for links that trip the phishing heuristics.

No network requests, no accounts, no data collection. Scoring happens entirely inside the extension's service worker.

## Install (load unpacked)

1. Clone or download this repository.
2. Open Chrome and go to `chrome://extensions`.
3. Turn on **Developer mode** (toggle in the top-right corner).
4. Click **Load unpacked** and select the `phishing-detector-extension` folder (the one containing `manifest.json`).
5. Open any web page and rest the cursor on a link for about half a second.

## How scoring works

Every URL starts at **100** and loses points for each heuristic it triggers.

| Heuristic | Penalty |
| --- | --- |
| `http://` instead of `https://` | -20 |
| Hostname is an IP address (v4 or v6) | -60 |
| Hostname contains more than 2 hyphens | -20 |
| Hostname contains `login`, `secure`, `verify`, `account` or `update` | -30 |
| Suspicious TLD (`.xyz`, `.top`, `.tk`, `.click`, ...) | -40 |
| Hostname longer than 40 characters | -15 |

The result is clamped to 1-100. **75 or higher** is shown as *Safe link*, anything lower as *Suspicious link*.

## Files

| File | Purpose |
| --- | --- |
| `manifest.json` | MV3 manifest: registers the service worker and the content script + stylesheet |
| `content.js` | Delegated hover handling on `<a>` tags, 400 ms debounce, tooltip rendering |
| `background.js` | Heuristic scoring engine running in the service worker |
| `styles.css` | Tooltip styling with `.safe` / `.warning` variants |

## Limitations

This is a heuristic, not a blocklist or a reputation service. Legitimate hosts that contain a flagged keyword (for example `accounts.google.com`) score lower than they deserve, and a carefully chosen phishing domain can still score high. Treat the badge as a hint, not a verdict.
