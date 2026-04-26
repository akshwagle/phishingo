# PhishFilter Pro — Browser Extension

Real-time phishing protection powered by 10 forensic engines and 5 AI models.

## Install in 30 seconds

1. **Download** — grab the latest `.zip` from [phishingo-zk3c.vercel.app/extension](https://phishingo-zk3c.vercel.app/extension) and unzip it to a permanent folder.
2. **Open extensions** — type `chrome://extensions` in your address bar.
3. **Enable Developer mode** — toggle in the top-right corner.
4. **Load unpacked** — click "Load unpacked", select the unzipped folder. Done.

Pin the shield icon to your toolbar for quick access.

## Features

| Feature | Description |
|---|---|
| **Live page guard** | Every page you visit is checked against threat feeds. Phishing sites get a full-screen block. |
| **Password sentinel** | Suspicious site? We block password input and warn you before you type. |
| **Smart link preview** | Hover any link for 1 second — see where it really leads plus a risk score. |
| **Gmail + Outlook scan** | One-click forensic scan on any email without leaving your inbox. |
| **Selection scanner** | Right-click any text or link → instant phishing check. |
| **Clipboard guardian** | Copy a suspicious URL? Get a notification immediately. |
| **Full page forensic scan** | Right-click → "Scan this entire page" — every link, form, and text block analyzed. |

## Permissions explained

| Permission | Why we need it |
|---|---|
| `activeTab` | Read the current tab's URL for the page guard check. |
| `tabs` | Watch for page loads to run the guard automatically. |
| `storage` | Save your settings, whitelist, and stats locally. |
| `contextMenus` | Add right-click scan options. |
| `notifications` | Alert you when a copied URL is dangerous. |
| `scripting` | Inject the block page and warning banner when needed. |
| `alarms` | Run the periodic health check every 5 minutes (service workers can't use `setInterval`). |
| `clipboardRead` | Check URLs you copy for threats. |
| `host_permissions: <all_urls>` | Check any URL you visit against our API. |

## Configure for self-hosting

Open the popup → Settings → change **Backend URL** to your own FastAPI instance.

## How to update

1. Download the new `.zip`.
2. Unzip to the **same folder** (overwrite files).
3. Go to `chrome://extensions` → click the refresh icon on PhishFilter Pro.

## Privacy

We send only the URL or email content you explicitly scan to our backend API for analysis. We do **not** track your browsing history, sell data, or store any personal information. All settings and stats are saved locally in your browser.

Source code: [github.com/akshwagle/phishingo](https://github.com/akshwagle/phishingo)

---

v1.0 · Powered by [Hack Club AI](https://ai.hackclub.com)
