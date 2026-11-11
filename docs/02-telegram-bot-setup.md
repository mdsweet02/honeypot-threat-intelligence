# 02 — Telegram Alert Bot: Step-by-Step

Goal: your honeypot sends you Telegram messages for **new malware**, **suspicious commands**, a **daily digest**, and **health problems**.

You need: the Telegram app (phone or desktop) and SSH access to the droplet.
Time: ~10 minutes.

---

## Step 1 — Create the bot with BotFather

1. Open Telegram and search for **`@BotFather`**. Pick the one with the **blue verified check mark**. Fake copies exist.
2. Tap **Start**, then send:
   ```
   /newbot
   ```
3. BotFather asks for a **name**. This is the display name and can be anything:
   ```
   Honeypot Alerts
   ```
4. BotFather asks for a **username**. It must be unique and **end in `bot`**:
   ```
   yourname_honeypot_bot
   ```
5. BotFather replies with a **token** that looks like this:
   ```
   7412345678:AAH3k9x-EXAMPLE-TOKEN-dQw4w9WgXcQ
   ```
   ⚠️ **Treat this token like a password.** Anyone who has it can send messages as your bot. Never commit it to GitHub or post it in a screenshot. If it leaks, send `/revoke` to BotFather to get a new one.

Optional polish (looks nice in screenshots for your portfolio):
- `/setuserpic`: upload an icon, such as a honeypot or shield.
- `/setdescription`: "Alerts from my Cowrie SSH honeypot."

---

## Step 2 — Start a chat with your bot

**A bot cannot message you until you message it first.**

1. Click the link BotFather gave you (`t.me/yourname_honeypot_bot`) or search for the username.
2. Tap **Start** (this sends `/start`).
3. Send any message, for example `hello`.

---

## Step 3 — Find your chat ID

Run this on the **droplet**. `read -s` keeps the token out of your shell history and off the screen:

```bash
read -rsp "Paste bot token: " TG_TOKEN; echo
```

```bash
curl -s "https://api.telegram.org/bot${TG_TOKEN}/getUpdates" | python3 -m json.tool
```

Look for this part of the output:
```json
"chat": {
    "id": 123456789,
    "first_name": "Your name",
    "type": "private"
}
```
**`123456789` is your chat ID.**

- If you see `"result": []`, send another message to the bot and run the command again.
- If you'd rather get alerts in a **group** (to share with classmates or a team), add the bot to the group, send a message in the group, and run `getUpdates` again. Group IDs are **negative** (e.g. `-1001234567890`).

---

## Step 4 — Send a test message by hand

```bash
read -rp "Chat ID: " TG_CHAT
```

```bash
curl -s -X POST "https://api.telegram.org/bot${TG_TOKEN}/sendMessage" -d chat_id="${TG_CHAT}" -d text="Hello from my honeypot 🍯"
```

You should get the message on your phone right away, and the output should include `"ok":true`.

| Error | Meaning / Fix |
|---|---|
| `401 Unauthorized` | Token is wrong: copy it again from BotFather |
| `400 chat not found` | Wrong chat ID, or you never pressed **Start** in the bot chat |
| `403 bot was blocked by the user` | You blocked the bot: unblock it in Telegram |

---

## Step 5 — Save the token and chat ID in `.env`

```bash
sudo nano /opt/honeypot/.env
```

```ini
TELEGRAM_BOT_TOKEN=7412345678:AAH3k9x-EXAMPLE-TOKEN-dQw4w9WgXcQ
TELEGRAM_CHAT_ID=123456789
```

```bash
sudo chmod 600 /opt/honeypot/.env
```

Then clear the variables from your shell:

```bash
unset TG_TOKEN TG_CHAT
```

---

## Step 6 — Test the honeypot's alert scripts

```bash
cd /opt/honeypot
```

```bash
sudo python3 scripts/healthcheck.py --test
```

You should get **"✅ Honeypot test message"**.

Preview the alerts against the sample data (prints only, sends nothing):

```bash
python3 scripts/telegram_alerter.py --file data/sample/cowrie-sample.json --once --dry-run
```

Send a real sample digest to your phone:

```bash
sudo python3 scripts/daily_digest.py --file data/sample/cowrie-sample.json --hours 0
```

After `infra/install.sh` has run, the live alerter runs as a service:

```bash
sudo systemctl restart honeypot-alerter
```

```bash
sudo journalctl -u honeypot-alerter -f
```

You should see `[alerter] following /opt/honeypot/data/cowrie/log/cowrie.json`.

---

## What alerts you will get

| Alert | When | Anti-spam |
|---|---|---|
| 🦠 **New malware file** | An attacker downloads (`wget`/`curl`) or uploads (SCP) a file whose SHA256 hash hasn't been seen before. Includes the VirusTotal verdict if `VT_API_KEY` is set. | Once per unique hash, ever |
| ⚠️ **Suspicious command** | SSH-key persistence, cron persistence, cryptominer, history clearing, disabling the firewall, creating users, changing passwords | Once per attacker IP per rule per hour, plus a global cap of 30/hour |
| 📊 **Daily digest** | 08:00 UTC: connections, unique IPs, logins, top usernames/passwords/commands/IPs, new files | Once a day |
| 🚨 **Health problem** | Cowrie container down, disk ≥ 80%, no new log events for 30 min, alerter/Filebeat stopped | Once when it breaks, once when it's fixed (`✅ Resolved`) |

Tune these in `.env`:
- `ALERT_COOLDOWN_SECONDS`
- `ALERT_MAX_PER_HOUR`
- `DISK_ALERT_PERCENT`
- `LOG_STALE_MINUTES`

To change the digest time, edit `/etc/cron.d/honeypot`. It uses **UTC**, so convert from your timezone.

All IPs and URLs in alerts are **defanged** (`hxxp://1[.]2[.]3[.]4`) so you can't open a malware link by accident on your phone. This is standard practice in threat intel.

---

## Security notes (worth mentioning in interviews)

- The bot only **sends** messages. It never reads commands, so a stranger who finds the bot can't control your server.
- The alerter runs under systemd `DynamicUser` (a temporary unprivileged user) with a read-only filesystem view.
- The token lives only in `/opt/honeypot/.env` (mode 600, git-ignored).
