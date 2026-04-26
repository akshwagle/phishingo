# PHISH-FILTER-PRO Frontend

Brutalist forensic email analysis UI — Cold War nuclear terminal aesthetic.

## Stack

- **Next.js 14** (App Router) + **React 18** + **TypeScript**
- **Tailwind CSS** with brutalist custom theme
- **JetBrains Mono** font (Google Fonts)
- **@react-pdf/renderer** for forensic PDF export
- **Web Audio API** for keyboard/alarm sound design

## Setup

```bash
cd frontend
npm install
# .env.local is already configured for localhost:8000
npm run dev
```

Open [http://localhost:3000](http://localhost:3000)

## Environment Variables

| Variable               | Default                    | Description                    |
|------------------------|----------------------------|--------------------------------|
| `NEXT_PUBLIC_API_URL`  | `http://localhost:8000`    | FastAPI backend URL            |

For production, set this in Vercel dashboard or `.env.production.local`.

## Usage Flow

1. Paste email / upload .eml / enter URL / paste text on the home page
2. Click **> EXECUTE FORENSIC SCAN_** — backend runs 8 engines + 5-model LLM ensemble (~30–90s)
3. Navigate to `/analyze/[job_id]` — WebSocket streams engine events into the terminal log
4. Full forensic report renders with verdict card, LLM ensemble panel, red flags, redirect chains

## Pages

| Route              | Description                             |
|--------------------|-----------------------------------------|
| `/`                | Input page — 4 input modes + recent feed |
| `/analyze/[id]`    | Live streaming analysis + full report   |

## Key Components

| Component             | Purpose                                           |
|-----------------------|---------------------------------------------------|
| `VerdictCard`         | Massive risk score with glitch/alarm effects      |
| `LLMEnsemblePanel`    | 5-model voting grid (Qwen3, Kimi-K2, DeepSeek…)  |
| `AuthBadges`          | SPF / DKIM / DMARC status badges with tooltips    |
| `RedFlagsList`        | Color-coded red flag evidence table               |
| `RedirectChain`       | URL hop visualizer with homograph detection       |
| `EngineGrid`          | 3×3 engine status grid with live pulse dots       |
| `TerminalLog`         | Auto-scrolling WebSocket event log                |
| `MatrixRain`          | Subtle matrix-rain canvas background              |

## Design System

```
#0A0A0A  — body background
#00FF41  — SAFE / Matrix green
#FFB800  — SUSPICIOUS / amber
#FF0044  — DANGEROUS / blood red
#E8E8E8  — neutral text (off-white)
#5A5A5A  — secondary text (dim gray)
```

No border-radius. No gradients. No shadows. Sharp corners everywhere.
CRT scanline overlay via `body::after`. JetBrains Mono on every element.

## Export Features

- **Export Forensic PDF** — full report rendered via `@react-pdf/renderer`
- **Copy Markdown Report** — pre-formatted markdown copied to clipboard
- **Report to Authorities** — APWG / FTC (reportfraud.ftc.gov) / IC3 (FBI) / Google Safe Browsing

## Sound Design

Muted by default. Toggle in the nav bar.
- Keyboard click on each keystroke (Web Audio API square wave)
- Double-beep when each engine completes
- 4-alarm stack on DANGEROUS verdict

Mute state is persisted to `localStorage`.

## Deploy to Vercel

```bash
vercel --prod
```

Set `NEXT_PUBLIC_API_URL` in Vercel → Project → Settings → Environment Variables.

Backend CORS already allows `*.vercel.app` origins.
