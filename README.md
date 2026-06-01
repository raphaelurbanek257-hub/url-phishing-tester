 # Phishing URL Detector

A command-line tool that checks if a URL is safe before you click it.

## Features

- Detects fake domains (paypal.com.xyz.net)
- Flags suspicious keywords (login, verify, secure)
- Identifies URL shorteners (bit.ly, tinyurl)
- Catches typosquatting (rnicrosoft.com)
- Checks for missing HTTPS
- Risk score from 0 to 100

## Installation

```bash
git clone https://github.com/raphaelurbanek257-hub/phish-detector.git
cd phish-detector
python phish_detector.py

