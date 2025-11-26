# PumpFun-airdrop-website-monitoring

Async watcher for pump.fun airdrop / claim endpoints with content fingerprinting, Telegram alerts, sound notifications, DNS (Domain Name System) and certificate transparency monitors, plus an offline guard for flaky networks.

## Features

* Polls a curated set of pump.fun URLs and auto-discovers new interesting endpoints from HTML.
* Detects “meaningful” positive responses using:

  * HTTP status and optional `only_when_200` filter.
  * Minimum body length.
  * Keyword matcher for airdrop / claim / rewards related terms.
  * Confirmation count (N consecutive positive checks) to reduce noise.
* Sends alerts via:

  * Telegram bot (single chat or broadcast to subscribers).
  * Local MP3 sound with simple cross‑platform fallbacks.
* Telegram quality-of-life:

  * `/start` / `/stop` subscription flow stored in `subscribers.json`.
  * Optional `/status` command.
  * Separate admin chat for startup pings.
* DNS monitor (optional, via dnspython):

  * Tracks A / AAAA records for a list of pump.fun subdomains.
  * Detects wildcard DNS and prints changes.
* Certificate Transparency monitor (optional, via certstream):

  * Watches CT logs for new `*.pump.fun` certs containing `airdrop` or `claim`.
* Offline guard:

  * Actively probes a list of URLs to decide whether the network is “online”.
  * Pauses HTTP / DNS / Telegram polling while offline.
  * Queues Telegram alerts and flushes them when connectivity returns.
  * Notifies on going offline / back online (optional).
* TLS / proxies:

  * Custom CA (Certificate Authority) bundle support.
  * Optional `certifi` integration.
  * Ability to disable certificate verification (not recommended).
  * Honors system proxy environment variables when enabled.
* Simple CSV logging to `pumpwatch_log.csv` for all events.

## Requirements

* Python 3.10 or newer.
* `aiohttp` (required).
* Optional but recommended:

  * `dnspython` for DNS monitoring.
  * `certstream` and its websocket dependencies for CT monitoring.
  * `playsound==1.2.2` or external players for MP3 alerts.
  * `certifi` for an up‑to‑date CA bundle.

## Installation

Create and activate a virtual environment (recommended):

```bash
python3 -m venv .venv
source .venv/bin/activate  # Linux / macOS
# .venv\Scripts\activate  # Windows PowerShell
```

Install dependencies:

```bash
pip install aiohttp dnspython certstream playsound==1.2.2 certifi
```

If you do not need DNS, CT or audio alerts you can install only `aiohttp`.

## Configuration

All behavior is controlled via a simple `config.env` file. Each line is a `KEY=VALUE` pair, with `#` used for comments. Quotes are supported for values that contain spaces.

Minimal example:

```env
# Core cadence
INTERVAL=1.0          # seconds between HTTP checks
HEARTBEAT=60          # seconds between “ALIVE” logs (0 to disable)

# Telegram alerts
TELEGRAM_ENABLED=true
TELEGRAM_BOT_TOKEN=123456789:ABCDEF_your_bot_token_here
TELEGRAM_CHAT_ID=123456789          # default chat
TELEGRAM_ADMIN_CHAT_ID=123456789    # admin chat for startup pings

# Positive signal definition
ONLY_WHEN_200=true
MIN_OK_LENGTH=600
CONFIRM=2

# Offline guard
OFFLINE_GUARD=true
OFFLINE_NOTIFY=true
OFFLINE_QUEUE_ALERTS=true
```

Key sections in `Config`:

* **Core cadence**

  * `INTERVAL` – base delay between HTTP polling cycles.
  * `HEARTBEAT` – how often to print an `ALIVE` message (seconds).
* **Positive signal**

  * `ONLY_WHEN_200` – require HTTP 200 OK for a positive signal.
  * `MIN_OK_LENGTH` – minimum response body length.
  * `CONFIRM` – how many consecutive “OK”s before raising an alert.
  * `ALERT_HOMEPAGE` – also treat the main `pump.fun` page as an alert source.
* **Alerts**

  * `ALERT_FILE` – path to MP3 used for audio alerts.
  * `NO_STARTUP_ALERTS`, `STARTUP_MUTE` – suppress noisy alerts immediately after startup.
* **Telegram**

  * `TELEGRAM_ENABLED` – master on/off.
  * `TELEGRAM_BOT_TOKEN`, `TELEGRAM_CHAT_ID`, `TELEGRAM_ADMIN_CHAT_ID`.
  * `TELEGRAM_PARSE_MODE` – `Markdown`, `MarkdownV2`, `HTML` or empty.
  * `TELEGRAM_SILENT` – send silent notifications.
  * `TELEGRAM_RETRY` – retry count on failures.
  * `TELEGRAM_BROADCAST_ALL` – if true, broadcast to all subscribers instead of a single chat.
  * `TELEGRAM_SUBSCRIBERS_FILE` – JSON file for subscriber list.
  * `TELEGRAM_POLL_UPDATES` – enable `/start` / `/stop` and `/status` handling.
* **Offline guard**

  * `OFFLINE_GUARD` – enable / disable the network watchdog.
  * `OFFLINE_PROBE_URLS` – comma‑separated URLs to test connectivity.
  * `OFFLINE_PROBE_INTERVAL` – delay between probes.
  * `OFFLINE_BACKOFF_BASE`, `OFFLINE_BACKOFF_MAX` – backoff tuning.
  * `OFFLINE_NOTIFY` – send Telegram notifications when going offline / online.
  * `OFFLINE_QUEUE_ALERTS` – queue alerts while offline and send them when back online.
* **TLS / proxies**

  * `SSL_CA_FILE` – custom CA bundle path (optional).
  * `SSL_NO_VERIFY` – turn off certificate verification (for debugging only).
  * `SSL_TRUST_ENV` – let `aiohttp` honor proxy environment variables.

See `Config` in `watchpump.py` for the full list of options and defaults.

## Running PumpWatch

With your virtual environment active and `config.env` ready:

```bash
python watchpump.py --config config.env
```

Useful flags:

* `--config PATH` – path to your config file (default: `config.env`).
* `--print-config` – print the parsed configuration and exit (no monitoring).

On startup PumpWatch logs the initial URLs it will watch and, if Telegram is enabled, sends a startup message to the admin chat.

## Telegram subscriptions

When `TELEGRAM_POLL_UPDATES=true`, PumpWatch will:

* Handle `/start` or `/subscribe` – add the chat to the subscriber list and send a welcome message.
* Handle `/stop` or `/unsubscribe` – remove the chat and send a goodbye message.
* Handle `/status` – reply with a short health summary.

Subscribers are stored in `subscribers.json` in the working directory.

## Logs

All events are appended to `pumpwatch_log.csv` with the columns:

* `ts_utc` – timestamp in Coordinated Universal Time.
* `signal` – event type (for example `ALERT_HTTP`, `DNS_CHANGE`, `NET_OFFLINE`).
* `key` – URL, host or other key.
* `detail` – human‑readable description.

You can import this file into a spreadsheet or script it for further analysis.

## Notes

* This tool is tailored specifically to pump.fun URLs and airdrop / claim related flows.
* Use TLS verification disabling options only for debugging in safe environments.
* Review the code and configuration before running in production or on always‑on servers.

## License

No explicit license is provided yet. If you plan to release this publicly, add a `LICENSE` file (for example the MIT License) and update this section accordingly.

