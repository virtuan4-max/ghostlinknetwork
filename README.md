# GhostLink Network — Flask App

A full-stack Flask web application that combines the GhostLink landing page, live
ecosystem map, bot launcher, streaming terminal, and visualizer into one tool.
Built using Claude (Sonnet 4.6 extended) for most of building/converting to a flask app + a bit of Google Gemini for UI.

xRevan
## Setup

```bash
pip install -r requirements.txt
python app.py
```

Then open **http://127.0.0.1:5000** in your browser.

## Routes

| Route | Description |
|---|---|
| `/` | Homepage with live CDN mini-map |
| `/launch` | Bot config + streaming terminal |
| `/visualizer` | Full D3 ecosystem visualizer |
| `/visualizer?session=ID` | Auto-loads + downloads session JSON |

## Flow

1. **Homepage** (`/`) — The map container auto-fetches and visualizes the live CDN
   ecosystem JSON. Click **Begin** to go to the launcher.

2. **Launcher** (`/launch`) — Enter your Discord user token (⚠ use a separate account),
   seed invite code, depth, and delay. Click **Launch Bot**. Output streams live to
   the terminal panel.

3. **After run** — Download the `ecosystem.json` and/or click **Open in Visualizer**
   which auto-loads the result into the full visualizer and triggers a browser download.

4. **Visualizer** (`/visualizer`) — Full D3 force-graph with settings, community
   detection, export, search, and node inspector. Can also load any `ecosystem.json`
   manually via drag-and-drop.

## Notes

- `bot.py` is **unchanged** — all original logic is preserved.
- The Flask server must be running for the bot API endpoints to work.
- Session JSON files are stored in `outputs/` during the server session (in-memory
  tracking, cleared on restart).
- Never use your main Discord account. Self-botting violates Discord's ToS.
