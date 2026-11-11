# 03 — Elastic Cloud (ELK) Setup: Step-by-Step

**When:** on **day ~3** of the capture. Filebeat sends all existing logs (including days 0–3), and the 14-day trial then runs until day ~17, which leaves time to analyze after capture ends.

**Why Elastic Cloud:** Elasticsearch needs 4 GB+ of RAM, which a $6 droplet doesn't have. Elastic Cloud runs Elasticsearch + Kibana for you. Only the lightweight **Filebeat** shipper (~50 MB of RAM) runs on the droplet.

```
Droplet: cowrie.json ──► Filebeat ──HTTPS:443 + API key──► Elastic Cloud
                                                           ├─ ingest pipeline "cowrie" (GeoIP, ASN)
                                                           └─ Kibana: Discover, Lens, Maps, Dashboards
```

---

## Step 1 — Start the trial and create a deployment

1. Go to **cloud.elastic.co/registration** and sign up. The free trial lasts 14 days and needs no credit card.
2. When asked what to create, choose **Elastic Cloud Hosted**, an **Elasticsearch / "general purpose"** deployment.
   - If it only offers **Serverless**, choose a **Security** or **Observability** project. Everything below still works; see the notes marked *Serverless*.
3. Cloud provider/region: pick one **near your droplet's region** (e.g. AWS/GCP Frankfurt for a DO Frankfurt droplet).
4. Wait about 3–5 minutes, then **write down the version** (e.g. `9.x.y` or `8.x.y`). Filebeat must use the **same major version**.

## Step 2 — Copy the Elasticsearch endpoint

Deployment page → **Manage** → **Elasticsearch: Copy endpoint**. It looks like:
```
https://my-honeypot-a1b2c3.es.europe-west3.gcp.cloud.es.io:443
```
That's your **ES_HOST**. (*Serverless:* Project → Settings / "Connection details" → Elasticsearch endpoint.)

## Step 3 — Create the ingest pipeline (GeoIP + ASN)

Open **Kibana** → menu ☰ → **Dev Tools** (Console).
Paste the full contents of [`elastic/ingest-pipeline.txt`](../elastic/ingest-pipeline.txt), put the cursor on `PUT _ingest/pipeline/cowrie`, and click ▶.
You should get `{"acknowledged": true}`.

Then run the `POST ..._simulate` request from the same file. The response should include `source.geo.country_name: "United States"` and `source.as.organization.name: "GOOGLE"`.

## Step 4 — Create an API key for Filebeat

Kibana → ☰ → **Stack Management → Security → API keys → Create API key**
- Name: `filebeat-honeypot`
- Expiration: 30 days
- Leave "Control security privileges" off (the default is fine for a personal trial).
- Click Create, then in the format dropdown choose **"Beats"**. The key looks like `AbCdEf123:ZyXwVu987...`. This is your **ES_API_KEY**. Copy it now: it's shown only once.

> Stricter alternative (good to mention in interviews: least privilege): turn on "Control security privileges" and give the key only `monitor`, `manage_index_templates`, `manage_ilm`, `manage_pipeline`, and on index `filebeat-*`: `create_doc`, `auto_configure`, `view_index_metadata`.

## Step 5 — Install Filebeat on the droplet

SSH in with `ssh -p 22222 hpadmin@DROPLET_IP`, then add Elastic's signing key:

```bash
wget -qO - https://artifacts.elastic.co/GPG-KEY-elasticsearch | sudo gpg --dearmor -o /usr/share/keyrings/elastic-keyring.gpg
```

Set `MAJOR` to your deployment's major version (`9` or `8`), then add the repository and install:

```bash
MAJOR=9
```

```bash
echo "deb [signed-by=/usr/share/keyrings/elastic-keyring.gpg] https://artifacts.elastic.co/packages/${MAJOR}.x/apt stable main" | sudo tee /etc/apt/sources.list.d/elastic.list
```

```bash
sudo apt update && sudo apt install -y filebeat
```

## Step 6 — Configure Filebeat (secrets go in the keystore, not the file)

Copy the config:

```bash
sudo cp /opt/honeypot/elastic/filebeat.yml /etc/filebeat/filebeat.yml
```

```bash
sudo chmod 600 /etc/filebeat/filebeat.yml
```

Store the secrets in Filebeat's encrypted keystore. Each `add` command asks you to paste the value:

```bash
sudo filebeat keystore create
```

```bash
sudo filebeat keystore add ES_HOST
```
Paste: `https://....es....cloud.es.io:443`

```bash
sudo filebeat keystore add ES_API_KEY
```
Paste: `id:key` (the "Beats" format)

Test it. Both must say `OK`:

```bash
sudo filebeat test config
```

```bash
sudo filebeat test output
```

Then start it:

```bash
sudo systemctl enable --now filebeat
```

```bash
sudo systemctl status filebeat --no-pager
```

> *Serverless:* if `test output` or the logs complain about ILM, add `setup.ilm.enabled: false` to `/etc/filebeat/filebeat.yml` and restart Filebeat.

## Step 7 — See your data in Kibana

1. Kibana → ☰ → **Discover** → **Create data view**
   - Name: `Cowrie`
   - Index pattern: `filebeat-*`
   - Timestamp field: `@timestamp`
2. Set the time picker to **Last 7 days**. You should see thousands of events within a minute or two.
3. Try these searches in the KQL bar:
   ```
   eventid : "cowrie.login.failed"
   eventid : "cowrie.login.success" and username : "root"
   eventid : "cowrie.command.input" and input : *wget*
   eventid : "cowrie.session.file_download"
   source.geo.country_iso_code : "CN"
   ```
4. Check the GeoIP enrichment: open any event. It should have `source.geo.country_name`, `source.geo.location`, and `source.as.organization.name`.

**Saved searches for the detections** (Sigma rules converted to KQL, see `detections/sigma/`). Save each one in Discover with **Save**:

| Name | KQL |
|---|---|
| SSH key persistence | `eventid:"cowrie.command.input" and input:*authorized_keys*` |
| Cryptominer | `eventid:"cowrie.command.input" and (input:*xmrig* or input:*stratum* or input:*minerd*)` |
| Download & execute | `eventid:"cowrie.command.input" and (input:*wget* or input:*curl*) and (input:*chmod* or input:*sh*)` |
| History clearing | `eventid:"cowrie.command.input" and (input:*"history -c"* or input:*HISTFILE* or input:*bash_history*)` |

---

## Step 8 — Build the dashboard (about 1 hour)

Kibana → ☰ → **Dashboards → Create dashboard → Create visualization**. This opens **Lens**: drag fields from the left onto the chart.

| # | Panel | Lens setup |
|---|---|---|
| 1 | **Metric tiles** | Metric → `Count`, filtered by `eventid:"cowrie.session.connect"`. Then Unique count of `src_ip`, and Count with `eventid:"cowrie.login.success"`. |
| 2 | **Attacks over time** | Bar/area: X = `@timestamp`, Y = Count, Break down by `eventid` (top 5) |
| 3 | **Attack map** | Use **Maps** (☰ → Maps) → Add layer → Documents → `Cowrie` → `source.geo.location`, or Clusters/heat map. Add it to the dashboard. |
| 4 | **Top countries** | Bar (horizontal): `source.geo.country_name` top 10, Count |
| 5 | **Top ASNs / hosting providers** | Table: `source.as.organization.name` top 10, Unique count of `src_ip` |
| 6 | **Top usernames / passwords** | Two tables: `username` top 15, and `password` top 15, each filtered by `eventid:cowrie.login*` |
| 7 | **Top commands** | Table: `input` top 20, filtered by `eventid:"cowrie.command.input"` |
| 8 | **SSH client fingerprints** | Donut: `version` (client.version events) and Table: `hassh` top 10 |
| 9 | **Malware downloads** | Table: `shasum`, `url`, `src_ip`, filtered by `eventid:"cowrie.session.file_download"` |
| 10 | **SSH vs Telnet** | Donut: `protocol` (on `cowrie.session.connect` events) |
| 11 | **Detections** | Add the saved searches from Step 7 as panels |

Name it **"Cowrie Honeypot — Threat Overview"** and **Save**.

> 💡 Field shows as "unknown" or can't be aggregated? Go to Stack Management → Data views → Cowrie → **Refresh field list**.

---

## Step 9 — Before the trial ends (by day ~16) ⚠️

When the trial ends, the deployment **and all its data are deleted**. Save everything first:

1. **Export the dashboard:** Stack Management → **Saved objects** → select the dashboard → **Export** (keep "include related objects" on). Save it as `elastic/kibana-dashboard.ndjson` in the repo. Anyone can import it into their own Kibana.
2. **Screenshots:** the full dashboard, the map, Discover showing an interesting session, the GeoIP-enriched event JSON, and the saved detection searches. Put them in `docs/images/`.
3. **CSV exports** you might need for the report: in Discover, use **Share → CSV report**.
4. Raw logs stay on the droplet in any case, so the Python scripts in doc 04 keep working.
5. Delete the API key, then the deployment (or just let the trial expire).
