# VeriLink

A multi-layered URL threat detection tool that checks a link against **Google Safe Browsing** and **VirusTotal** (70+ security engines) before you click it.

## How it works

- The frontend (`public/`) is a simple dashboard — paste a URL, hit Scan.
- The backend (`server.js`) is the only thing that talks to Google/VirusTotal. Your API keys never touch the browser, which is important — client-side code is publicly visible, so keys embedded there can be stolen and abused.
- Results from both services are combined into one verdict: **Threat detected**, **Suspicious**, **No threats found**, or **Unable to verify**.

## Setup

1. **Install Node.js** (v18 or newer) if you don't have it: https://nodejs.org

2. **Install dependencies**
   ```bash
   npm install
   ```

3. **Add your API keys**
   ```bash
   cp .env.example .env
   ```
   Open `.env` and paste in your real keys:
   - Google Safe Browsing key: https://developers.google.com/safe-browsing/v4/get-started
   - VirusTotal key: https://www.virustotal.com/gui/my-apikey

4. **Run it**
   ```bash
   npm start
   ```
   Then open http://localhost:3000

## Notes on the APIs

- **VirusTotal free tier** allows 4 requests/minute and 500/day. If a URL hasn't been scanned before, VeriLink submits it and polls for results — this can take 10–15 seconds.
- **Google Safe Browsing** is free with generous limits and responds instantly.
- If a URL scan is still "Pending" from VirusTotal, just scan it again in a few seconds — it'll usually be cached by then.

## Deploying it live

This app needs a server (not just static hosting like Netlify Drop), because the backend is what protects your API keys. Good free options:

- **Render** (render.com) — free tier, connect a GitHub repo, auto-deploys on push
- **Railway** (railway.app) — similar, free tier with usage limits
- **Vercel** — works if you convert `server.js` into serverless functions (a bit more setup)

For any of these: push this project to a GitHub repo, connect the repo, and add your `GOOGLE_SAFE_BROWSING_API_KEY` and `VIRUSTOTAL_API_KEY` as environment variables in their dashboard (never commit your real `.env` file).

## Project structure

```
verilink/
├── server.js          # Express backend — API integrations live here
├── package.json
├── .env.example        # Copy to .env and fill in your keys
├── public/
│   ├── index.html      # Dashboard UI
│   ├── styles.css
│   └── app.js           # Frontend logic — calls /api/check
└── README.md
```
