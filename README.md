# Q3 Server Browser

A native desktop server browser for **Quake 3 Arena**, written in Python with PyQt6.

No dependencies beyond Python 3 and PyQt6 — no web stack, no Electron.

## Features

- **Master server query** — fetches servers from `master.ioquake3.org` (protocol 68)
- **Parallel scanning** — queries all servers concurrently (50 threads) for fast results
- **Server list** — sortable table with name, gametype, map, players, ping, address
- **Player list** — displays scores, pings, and names with Q3 color codes (^0–^9)
- **Favorites** — click the star to mark/unmark; favorites float to the top when sorting
- **Text filter** — real-time filtering by server name or map
- **Hide empty servers** — toggle to hide servers with 0 players
- **RCON** — full RCON tab with command input and quick-buttons (status, kick, ban, map, say)
- **One-click connect** — double-click launches Q3 with `+connect ip:port`
- **Proton support** — optionally launch Q3 through Proton via `protontricks-launch`
- **Auto-refresh** — configurable interval for background updates
- **Settings persist** — exe path, RCON password, Proton config, window geometry, favorites stored in `~/.config/q3browser.ini`

## Requirements

- Python 3.10+
- PyQt6 (`python-pyqt6` on Arch, `pyqt6` on pip)

## Installation

```bash
pip install PyQt6
```

## Usage

```bash
python3 q3browser.py
```

Open **Settings (Ctrl+P)** to set:
- **Q3 Path** — path to your Q3 executable (e.g. `quake3e.x64.exe` or `quake3.x86`)
- **Proton** — enable and set a Steam AppID to launch via `protontricks-launch`
- **RCON password**, **master server**, **auto-refresh interval**

## Project structure

- `q3browser.py` — single-file application (~1050 lines)
- `requirements.txt` — `PyQt6>=6.5`
