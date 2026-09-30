# Demo: a botnet investigation on real traffic (CTU-13)

A 5–10 minute investigation with known answers, on real network flows
rather than synthetic data. Every number below was measured with gridsift
on the files named here and can be reproduced from the commands; the
labels in the dataset are the ground truth.

## The data

**CTU-13** — thirteen botnet captures made at the Czech Technical
University in 2011 (Stratosphere Laboratory). Each scenario ran one
malware sample on a lab host inside the university network while the
router captured everything; the published bidirectional NetFlows carry a
`Label` per flow: *Background*, *Normal*, or *Botnet* (with the botnet
labels naming the traffic kind, e.g. `flow=From-Botnet-V42-TCP-CC`).

- Licence: **CC BY 2.0** (the dataset's README). Cite:
  S. García, M. Grill, J. Stiborek, A. Zunino, *An empirical comparison of
  botnet detection methods*, Computers & Security 45 (2014) 100–123.
- Dataset page: https://www.stratosphereips.org/datasets-ctu13 ; files:
  https://mcfp.felk.cvut.cz/publicDatasets/CTU-Malware-Capture-Botnet-NN/
- What to download: only the labelled flow file of each scenario,
  `capture<date>.binetflow.2format` — a plain CSV with a header and 33
  columns (`SrcAddr, DstAddr, Proto, Sport, Dport, State, …, StartTime,
  LastTime, …, TotPkts, TotBytes, …, Label`). **Do not download the
  scenario tarball or `only-exes-of-ctu-13.zip`: they contain the malware
  samples.** The pcaps are not needed either.
- Addresses are real (2011): the infected lab hosts are `147.32.84.x`
  (CVUT), the botnet destinations are wherever the malware talked to
  fifteen years ago. GeoIP / ASN annotations therefore come from a
  *current* database and describe today's allocation of those addresses.

| scenario | directory | malware | flow file | size | duration |
|---:|---|---|---|---:|---|
| 1 | Botnet-42 | Neris | `capture20110810.binetflow.2format` | 696 MB | 6.15 h |
| 2 | Botnet-43 | Neris | `capture20110811.binetflow.2format` | 444 MB | 4.21 h |
| 3 | Botnet-44 | Rbot | `capture20110812.binetflow.2format` | 1,159 MB | 66.85 h |
| 4 | Botnet-45 | Rbot | `capture20110815.binetflow.2format` | 277 MB | 4.21 h |
| 5 | Botnet-46 | Virut | `capture20110815-2.binetflow.2format` | 32 MB | 11.63 h |
| 6 | Botnet-47 | Menti | `capture20110816.binetflow.2format` | 138 MB | 2.18 h |
| 7 | Botnet-48 | Sogou | `capture20110816-2.binetflow.2format` | 28 MB | 0.38 h |
| 8 | Botnet-49 | Murlo | `capture20110816-3.binetflow.2format` | 729 MB | 19.5 h |
| 9 | Botnet-50 | Neris | `capture20110817.binetflow.2format` | 515 MB | 5.18 h |
| 10 | Botnet-51 | Rbot | `capture20110818.binetflow.2format` | 323 MB | 4.75 h |
| 11 | Botnet-52 | Rbot | `capture20110818-2.binetflow.2format` | 26 MB | 0.26 h |
| 12 | Botnet-53 | NSIS.ay | `capture20110819.binetflow.2format` | 81 MB | 1.21 h |
| 13 | Botnet-54 | Virut | `capture20110815-3.binetflow.2format` | 474 MB | 16.36 h |

(Sizes are the HTTP `Content-Length` of each file on 2026-09-30; durations
from the dataset paper.)

### Enrichment data

**DB-IP Lite** (https://db-ip.com/db/lite.php), the September 2026
editions, CC BY 4.0 — attribution *"IP Geolocation by DB-IP"* is required
wherever results are shown. No registration is needed:

| file | size | SHA-256 |
|---|---:|---|
| `dbip-country-lite-2026-09.mmdb` | 8,340,464 | `d284ae2e7427fe33d83465e1506b2b21aae47eb8a9b099f8f4dac6a98c99f041` |
| `dbip-asn-lite-2026-09.mmdb` | 9,511,026 | `ab07c764a10c4f8c2f3539377fa86e5c928243084aafd359d1be4cb8543d7406` |

## Getting the data

Everything goes into the repository's ignored `demo/` directory:

```
export PATH="$PWD/target/release:$PATH"
mkdir -p demo/ctu13 demo/geoip && cd demo

B=https://mcfp.felk.cvut.cz/publicDatasets
curl -L -o ctu13/s11.csv $B/CTU-Malware-Capture-Botnet-52/capture20110818-2.binetflow.2format
curl -L -o ctu13/s01.csv $B/CTU-Malware-Capture-Botnet-42/capture20110810.binetflow.2format

curl -L https://download.db-ip.com/free/dbip-country-lite-2026-09.mmdb.gz | gunzip > geoip/dbip-country-lite-2026-09.mmdb
curl -L https://download.db-ip.com/free/dbip-asn-lite-2026-09.mmdb.gz     | gunzip > geoip/dbip-asn-lite-2026-09.mmdb

gridsift hash ctu13/s11.csv     # compare with the table below
```

The server is not fast (about 0.5 MB/s in total on 2026-09-30); scenario
11 arrives in a minute, scenario 1 in about half an hour.

## Known answers

Measured with gridsift 0.1.0 (`main` at `830d714`) and cross-checked: the
record count is the count of Python's `csv` module on the same file, the
botnet / normal counts are the `Label` column, and the scenario totals are
the ones the dataset paper reports.

| scenario | SHA-256 of the flow file | records | botnet flows | normal flows | first … last `StartTime` (UTC) |
|---:|---|---:|---:|---:|---|
| 5 | `f6fd1d0fd8e13cbd54a2e8e5235dc6dce0d2beee58b78ce2c176646cf00c3807` | 129,832 | 901 | 4,660 | 2011-08-15 16:43:20 … 17:13:26 |
| 7 | `8cc97aaea02190817675ba55eb924eeb7958986790f09f46650d8a360f5723cb` | 114,077 | 63 | 1,669 | 2011-08-16 13:51:24 … 14:12:41 |
| 11 | `a78e3a297fd07fe4b9a076a93c94b06732679947d96179ebe662cec4339374fc` | 107,251 | 8,164 | 2,709 | 2011-08-18 15:39:35 … 15:55:46 |

Scenario 11 (Rbot, 16 minutes) is the quick one for a rehearsal; scenario
1 (Neris, 6 hours, 696 MB) is the one for the video. Its row is added to
the table once measured.

## The investigation (command line)

Scenario 11, `demo/ctu13/s11.csv`:

```
gridsift info  ctu13/s11.csv                         # ',' quote '"' header · 33 columns
gridsift index ctu13/s11.csv                         # 107,251 records · 0 malformed · SHA-256 a78e3a29…
gridsift profile ctu13/s11.csv                       # SrcAddr/DstAddr ipv4 · Sport/Dport port · StartTime timestamp · Proto/State/Label categorical
gridsift freq  ctu13/s11.csv -c Label -n 8           # 58 distinct labels; Background-UDP-Established 37,342 on top
gridsift search ctu13/s11.csv From-Botnet -c Label   # 8,164 matches
gridsift search ctu13/s11.csv From-Normal -c Label   # 2,709 matches
gridsift timeline ctu13/s11.csv -c StartTime -b 1m   # 17 one-minute buckets, 100 % parsed
gridsift freq  ctu13/s11.csv -c DstAddr.country -s From-Botnet \
    --geoip DstAddr=geoip/dbip-country-lite-2026-09.mmdb        # CZ 8,155 · US 8 · FR 1
gridsift freq  ctu13/s11.csv -c Dport -s From-Botnet -n 5      # 0x0000 (ICMP) 7,663 · 53 · 123 · 6667 · 80
gridsift export ctu13/s11.csv -o s11-botnet.csv -s From-Botnet -c Label \
    --geoip DstAddr=geoip/dbip-asn-lite-2026-09.mmdb --redact SrcAddr=ip:16
                                                     # 8,164 records · operations: search, enrich, redact
gridsift verify s11-botnet.csv --require-source      # ok · scope output+source
```

What the answers mean: this Rbot sample spent its sixteen minutes
scanning the university's own network (8,143 of its 8,164 flows are ICMP,
almost all to `147.32.0.0/16`, hence *CZ*), with a handful of DNS, NTP,
IRC (6667 — the C&C channel) and HTTP flows. The export carries the ASN of every
destination, the infected host's address truncated to its /16, and a
manifest naming the flow file, the DB-IP database and every step by
hash.

## The investigation (desktop, the video)

Scenario 1, `demo/ctu13/s01.csv` (Neris: spam, click fraud and C&C over
six hours):

```
gridsift-desktop ctu13/s01.csv
```

1. **Open.** Rows are on screen at once; the sidebar shows the SHA-256
   arriving and the record count settling; columns are typed (`StartTime`
   timestamp, addresses, ports, `Label` categorical).
2. **Dashboard.** Timeline of six hours; pies for `Proto` and `State`;
   top values of `DstAddr`, `Dport`, `Label`.
3. **Search** `From-Botnet` in `Label`: a chip with the botnet flow count;
   every chart recounts within it. The timeline now shows *when* the bot
   was active.
4. **Pivot.** Click `6667` in the `Dport` bars (IRC — the C&C channel) or
   the top `DstAddr`: a second, exact-match chip.
5. **Enrich.** *Enrich…* → `DstAddr` → GeoIP with the DB-IP ASN file:
   `DstAddr.asn`, `DstAddr.as_org` appear in green; *Count values* on
   `DstAddr.as_org` shows which networks the bot talked to.
6. **Export finding…** with `SrcAddr` → ip prefix /16 and the derived
   columns included; the dialog lists the two selection steps, the
   enrichment rule and the redaction rule that the manifest will record.
7. **Verify** on the command line: `gridsift verify finding.csv
   --require-source`.

Nothing in these steps modified `s01.csv`; the manifest is the record of
what was derived.

## Notes for the recording

- Show the attribution once: "IP Geolocation by DB-IP", and the CTU-13
  citation.
- The addresses are 2011 addresses: say so when the ASN column appears.
- `Sport` / `Dport` are hexadecimal for ICMP (`0x0000`) and decimal
  otherwise; `Dport` is typed `port` because the header says so.
- `freq`'s `-s` search is over the whole record; restrict with the desktop
  search (column chip) when a column-scoped selection matters.
