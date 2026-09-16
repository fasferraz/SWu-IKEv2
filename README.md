# SWu-IKEv2

Python 3 IKEv2 / IPsec SWu UE client (3GPP TS 33.402). It runs the IKE control plane and userspace ESP, and creates a TUN with the CFG_REPLY inner addresses.

This tree is **version2**: YAML config, software AKA, Lima on macOS, interactive rekey/reauth, DPD / NAT-T keepalive, and negative-test profiles. It started from [fasferraz/SWu-IKEv2](https://github.com/fasferraz/SWu-IKEv2).

IKE and TUN need Linux. On a Mac the TUN stays in a Lima Ubuntu guest. The Mac host never gets a tunnel interface.

## Run on macOS

```
brew install lima
./run-lima.sh
```

`run-lima.sh` starts (or reuses) instance `swu`, installs a guest venv at `~/.cache/swu-venv`, and always adds `--no-default-route --no-dns`. Guest default route and `/etc/resolv.conf` stay off the TUN.

```
./run-lima.sh --ephemeral          # throwaway instance, deleted on exit
./run-lima.sh -- --reconnect 3
./run-lima.sh --test
./run-lima.sh --test -- test_swu_config
```

`./run.sh` on Darwin exits and points here. Software AKA (`imsi` / `ki` / `op` or `opc`) works. A USB SIM reader does not (no USB passthrough). If the ePDG is on the Mac, set `dest` to `host.lima.internal`. A dest only on `192.168.64.0/24` may be invisible through vzNAT.

## Config

`swu.yaml` is the dummy sample (3GPP TS 35.208 set-1, dest `192.168.64.1`). For a real subscriber:

```
cp swu.yaml swu.lab.yaml
```

Edit `dest`, `imsi`, `ki`, `opc` (or `op`), `mcc`, `mnc`, and `apn`. Quote IMSI / Ki / OP / OPc / IMEI so leading zeros survive YAML.

`swu.lab.yaml` is gitignored. Do not commit Ki or OPc.

`./run.sh` and `./run-lima.sh` pick `swu.lab.yaml` when it exists, else `swu.yaml`. Override with `SWU_CONFIG=path.yaml`. CLI values win over the file.

The sample CFG_REQUEST / traffic selectors are IPv6-only. Uncomment `INTERNAL_IP4_*` / `TS_IPV4_*` / `P_CSCF_IP4_*` in the **active** file (`swu.lab.yaml` if you copied one) for IPv4 or dual-stack.

`apn` is sent as IDr FQDN as-is. `mcc` / `mnc` build the IDi NAI:

```
# IDi  0<imsi>@nai.epc.mnc<mnc>.mcc<mcc>.3gppnetwork.org
# IDr  <apn>
```

If `IKE_SA_INIT` comes back `INVALID_KE_PAYLOAD`, the client keeps only proposals whose DH group matches the notify and retries. Success prints `event=connected ...` and:

```
STATE CONNECTED. Press q to quit, i to rekey ike, c to rekey child sa, r to reauth.
```

| Key | Action |
|---|---|
| `i` | IKE SA rekey |
| `c` | Child SA rekey |
| `r` | full reauth (new attach) |
| `q` | tear down and exit |

SIGINT / SIGTERM tear down during IKE and CONNECTED (IKE DELETE if keys exist). IKE_AUTH resends the same packet twice on UDP timeout. `--headless` (or YAML `headless: true`) stays CONNECTED without reading the keyboard. Needed with no TTY and for the negative-test profiles. `run-lima.sh` from a terminal is interactive.

## Run on Linux

```
./install_deps.sh
./run.sh
```

`install_deps.sh` is tested on Ubuntu 22.04 / 24.04. It needs either root or `cap_net_bind_service,cap_net_raw,cap_net_admin=+ep` on the venv `python3` (port 500, raw ESP, TUN). The script copies the interpreter so `setcap` hits the venv binary, not system `python3`.

Physical smartcard / modem:

```
./install_deps.sh --with-usim
```

Without a reader, pass `--imsi` and `--ki` with `--op` or `--opc`. The client exits instead of using dummy CK/IK/RES.

## Routing

`--no-default-route` (always on from `run-lima.sh`) leaves only the CFG_REPLY inner `/32` or `/128` on the TUN, plus host routes for CFG_REPLY DNS and P-CSCF. Other destinations stay on the guest default. A ping sourced from an address that is not one of those host routes needs a matching tun route on the UE, or it will not go back through ESP.

Without `--no-default-route`, Linux still installs the original split default (`0.0.0.0/1` + `128.0.0.0/1`, IPv6 `::/1` + `8000::/1`) so it wins over `0/0`, plus a host route to the ePDG via the old gateway (`-g` to pick the gateway). Teardown removes the TUN and restores DNS if `--no-dns` was not set.

## Options

```
python3 swu_emulator.py -h
```

| Flag / YAML | Meaning |
|---|---|
| `--config FILE.yaml` | CLI keys plus `ike_sa`, `child_sa`, `ts_initiator`, `ts_responder`, `cp`. Names are identifiers in `ikev2_const.py`. |
| `--imsi` / `--ki` / `--op` / `--opc` | Software AKA (Milenage) |
| `--mcc` / `--mnc` | IDi NAI (USIM), 3 digits |
| `--apn` | IDr FQDN |
| `--dest` | ePDG address or FQDN |
| `--no-default-route` | Do not install `0/1` + `128/1` (or IPv6 `::/1` + `8000::/1`) on the TUN |
| `--no-dns` | Do not overwrite `/etc/resolv.conf` |
| `--headless` | No `q`/`i`/`c`/`r` |
| `--imei` / `--imeisv` | DEVICE_IDENTITY (defaults `123456789012347` / `1234567890123456`) |
| `--log-level` | `debug` / `info` / `warning` / `error`. Hex dumps are `info`. `event=connected` and `event=failed` / `event=retry` always print. |
| `--dpd SECONDS` | Empty INFORMATIONAL liveness while CONNECTED. `0` off. Default 30, or ePDG `TIMEOUT_PERIOD_FOR_LIVENESS_CHECK`. Two missed replies → `event=failed reason=LIVENESS_TIMEOUT`. |
| `--keepalive SECONDS` | RFC 3948 NAT-T `0xFF` on UDP 4500 when NAT is detected. `0` off. Default 20. |
| `--reconnect N` | Restart IKE after peer IKE DELETE or liveness timeout. `0` off (default). Prints `event=retry reason=RECONNECT`. Not MOBIKE. `q` / SIGINT still exit. Keyboard `r` does not consume a reconnect. |
| `--export-keys DIR` | Append Wireshark `ikev2_decryption_table` and `esp_sa` (also on rekey) |
| `--netns NAME` | TUN inside that network namespace |
| `-m` / `--modem` | `COMX`, `/dev/ttyUSBX`, PC/SC reader index, or HTTPS USIM server |

## Negative-test profiles

Dummy-ePDG fixtures (`192.168.64.1` / 3GPP set-1 IMSI), same subscriber as `swu.yaml`, not `swu.lab.yaml`. One knob per file. Expected `event=` line is in the file header.

```
python3 swu_emulator.py --config profiles/invalid_ke.yaml
python3 swu_emulator.py --config profiles/no_proposal.yaml
python3 swu_emulator.py --config profiles/auth_failed.yaml
python3 swu_emulator.py --config profiles/auts_sync.yaml
python3 swu_emulator.py --config profiles/user_unknown.yaml
python3 swu_emulator.py --config profiles/no_apn.yaml
python3 swu_emulator.py --config profiles/illegal_me.yaml
```

| Profile | Knob | Typical event |
|---|---|---|
| `invalid_ke.yaml` | KE is MODP_768, then MODP_2048 | `event=retry notify=INVALID_KE_PAYLOAD` |
| `no_proposal.yaml` | IKE offers only ENCR_DES | `event=failed notify=NO_PROPOSAL_CHOSEN code=14` |
| `auth_failed.yaml` | Ki last byte flipped | `event=failed reason=EAP_FAILURE` or `notify=AUTHENTICATION_FAILED` |
| `auts_sync.yaml` | `sqn` set | `event=retry reason=SYNC_FAILURE` |
| `user_unknown.yaml` | unknown IMSI | `event=failed notify=USER_UNKNOWN code=9001` |
| `no_apn.yaml` | `apn: nosuch.apn` | `event=failed notify=NO_APN_SUBSCRIPTION code=9002` |
| `illegal_me.yaml` | IMEI 15 zeros | `event=failed notify=ILLEGAL_ME` or `IMEI_NOT_ACCEPTED` |

24.302 codes depend on the ePDG/HSS. Numeric notifies are named (`code=24` → `AUTHENTICATION_FAILED`).

## Tests

```
python3 -m unittest test_swu_config
python3 -m unittest test_usim_aka
python3 -m unittest test_dh
./run-lima.sh --test
```

`test_usim_aka` uses 3GPP TS 35.208 set 1 (including AUTS / f1* / f5*).

## Protocol

SWu is IKEv2 between UE and ePDG. IDi / IDr carry NAI and the ePDG FQDN so the ePDG can run EAP-AKA against AAA/HSS. After Diffie-Hellman, IKE is encrypted. CFG_REPLY can include inner IPv4/IPv6, DNS, P-CSCF, and liveness timeout.

<p align="center"><img src="images/ePDG_Keys.png" width="100%"></p>

<p align="center"><img src="images/ePDG_Flow.png" width="100%"></p>

Three processes: IKE on the main process; ESP encoder (TUN → ePDG); ESP decoder (ePDG → TUN, and NAT-T IKE on UDP 4500).

<p align="center"><img src="images/SWu_Emulator.png" width="100%"></p>

Supported:

- IKEv2 RFC 5996 / 7296
- EAP-AKA RFC 4187; EAP Identity (RFC 3748 type 1) before AKA when the ePDG asks
- IKE ENCR: AES-CBC-128/256, NULL
- IKE PRF: HMAC-MD5, SHA1, SHA2-256/384/512
- IKE INTEG: HMAC-MD5-96, SHA1-96, SHA2-256-128, SHA2-384-192, SHA2-512-256
- DH: groups 1, 2, 5, 14–18 and ECP 19 / 20 / 21 (P-256 / P-384 / P-521)
- ESP: AES-CBC-128/256, AES-GCM-8/12/16, NULL
- No certificates
- NAT-T; IKE on UDP 500 or 4500; ESP or ESP-in-UDP 4500
- Fast reauthentication; IKE and Child rekey (UE or ePDG initiated)

Proposals live in YAML (`ike_sa` / `child_sa`). Names are `ikev2_const.py` identifiers.

`--export-keys DIR` writes the IKE decrypt table and ESP SA lines Wireshark wants (appended on rekey). The same lines are printed at CONNECTED.

IKE `ENCR_NULL` is not in the RFC. `self.sk_ENCR_NULL_pad_length` is `0` or `1` depending on whether the peer expects a pad-length octet.

USIM AKA (RAND/AUTN → RES/CK/IK) can also come from `AT+CSIM`, pyscard + [mitshell/card](https://github.com/mitshell/card), or [fasferraz/USIM-https-server](https://github.com/fasferraz/USIM-https-server).
