# Deploying vhlocal (Linux backend + remote GPU)

vhlocal is **stdlib-only Python 3.9+** — no `pip install`, no build step. It runs
the same on Linux and macOS. The only moving part is *which inference server it
talks to*, which is entirely configuration.

## Architecture

```
  ┌─────────────────────────┐        HTTP (LAN)        ┌────────────────────────┐
  │  Ubuntu VM (Proxmox)     │  ───────────────────▶   │  RTX 6000 box          │
  │  vhlocal server + UI     │   /api/chat (Ollama)    │  ollama serve          │
  │  git clone, python3      │                         │  gpt-oss:120b in VRAM  │
  └─────────────────────────┘                          └────────────────────────┘
```

The backend (orchestrator + web UI) and the GPU are separate hosts. vhlocal on
the VM sends chat requests to Ollama on the RTX 6000. Reports and the repo under
scan live on the VM; only chat traffic crosses the network (negligible — see
RUNBOOK §runtime).

## 1. On the Ubuntu VM (backend)

```bash
git clone <your-repo-url> vhlocal && cd vhlocal
python3 --version            # 3.9+ ; nothing to install
python3 -m unittest discover -s tests   # optional sanity check
```

The vulnhunt skill is **bundled** (`skill/`), so there is nothing else to fetch.

Point it at the GPU box and run a scan:

```bash
export VHLOCAL_OLLAMA_HOST=http://<rtx6000-ip>:11434
python3 -m vhlocal.run --repo /path/to/target --verify-model qwen3.5:122b-a10b
```

Or run the web UI (see §3 for LAN exposure):

```bash
python3 -m vhlocal.server --ollama-host http://<rtx6000-ip>:11434
# open http://127.0.0.1:8420  (loopback by default)
```

## 2. On the RTX 6000 box (Ollama)

```bash
ollama pull gpt-oss:120b
# Bind Ollama to an interface the VM can reach (NOT 0.0.0.0 on an untrusted net):
export OLLAMA_HOST=0.0.0.0:11434         # or a specific LAN IP
# Parallel slots (see RUNBOOK for the concurrency lever), via systemd:
sudo systemctl edit ollama               # add: Environment="OLLAMA_NUM_PARALLEL=2"
sudo systemctl daemon-reload && sudo systemctl restart ollama
```

The Ollama endpoint is **unauthenticated** — keep it on a private/VLAN interface
or firewall the port to the VM only.

## 3. Exposing the vhlocal web UI on the LAN

The server binds `127.0.0.1` by default and **refuses** a non-loopback bind
without an explicit acknowledgement, because it executes scans:

```bash
python3 -m vhlocal.server --host 0.0.0.0 --unsafe-bind \
    --ollama-host http://<rtx6000-ip>:11434
```

Prefer instead to keep it on loopback and reach it over an **SSH tunnel**:

```bash
ssh -L 8420:127.0.0.1:8420 user@<vm-ip>     # then open http://127.0.0.1:8420 locally
```

## 4. Keeping the macOS / Apple-Silicon option

The backend choice is a config, so the *same code* runs against Apple Metal or MLX:

```bash
# Ollama on the Mac (llama.cpp/Metal) — just change the host:
python3 -m vhlocal.run --repo <target> --host http://localhost:11434

# MLX on Apple Silicon (OpenAI-compatible server):
mlx_lm.server --model <mlx-gpt-oss-quant> --port 8080
python3 -m vhlocal.run --repo <target> --backend openai --host http://localhost:8080
```

Measure before trusting a new backend: `python3 -m vhlocal.bench` (Ollama) vs
`python3 -m vhlocal.bench --backend openai --host http://localhost:8080` (MLX),
then diff findings on a small scan (see RUNBOOK §4c).

## 5. Optional: run the vhlocal server as a systemd service

```ini
# /etc/systemd/system/vhlocal.service
[Unit]
Description=vhlocal scan engine
After=network-online.target

[Service]
User=vhlocal
WorkingDirectory=/opt/vhlocal
Environment=VHLOCAL_OLLAMA_HOST=http://<rtx6000-ip>:11434
ExecStart=/usr/bin/python3 -m vhlocal.server --ollama-host ${VHLOCAL_OLLAMA_HOST}
Restart=on-failure

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload && sudo systemctl enable --now vhlocal
```

## Config reference (all optional)

| Setting | Env | Flag | Default |
|---|---|---|---|
| Inference host | `VHLOCAL_OLLAMA_HOST` | `--host` / `--ollama-host` | `http://localhost:11434` |
| Backend | — | `--backend {ollama,openai}` | `ollama` |
| Reports dir | — | `--reports-dir` | `~/vulnhunter-reports` |
| Central log | `VHLOCAL_LOG_FILE` / `VHLOCAL_LOG_DIR` | `--log-file` | `~/.vhlocal/vhlocal.log` |
| Skill dir | — | `--skill-dir` | bundled `skill/` |
| Verify model | — | `--verify-model` | (none — same model) |
