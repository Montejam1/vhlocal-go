## Application characterization

**Stage I – Objectives & assets**
The target is a Python FastAPI service that provides a logistics dispatch system. It exposes a public REST API for authentication, user and customer management, job and incident handling, as well as an internal operations namespace (`/ops/*`) used by privileged services. Crown‑jewel assets include:
- User credentials and session tokens (JWT‑style tokens, password hashes).
- Personally identifying information (PII) such as email, phone, SSN, and credit‑card numbers stored in the JSON vault endpoint.
- Operational data (jobs, incidents, dispatcher‑region assignments) that drive field dispatch decisions.
- The ability to execute code on the host (via unsafe deserialization/eval) which can lead to full server compromise.

**Stage II – Technical scope**
- **Archetype:** Web service / REST API built with **FastAPI** (Python 3) and a thin TypeScript front‑end client.
- **Stack & notable dependencies:**
  - FastAPI, Pydantic (request validation)
  - SQLAlchemy (SQL DB), PyMongo (MongoDB)
  - Jinja2 (templating), lxml (XML parsing), pickle (binary deserialization)
  - bcrypt/passlib (password hashing)
  - uvicorn (ASGI server)

---

## Data flow diagram
```mermaid
flowchart TD
    subgraph TB1["Attacker"]
        A["HTTP request"]
    end
    subgraph TB2["Application"]
        B["FastAPI router (public /api/*)"]
        C["FastAPI router (/ops/*) – internal ops"]
        D["Internal Ops Gate (x‑internal‑token) "]
        E["Dispatch operation handlers"]
        F["Database (SQLAlchemy / MongoDB)"]
        G["Filesystem (BASE_EXPORT_DIR)"]
        H["External services (email, etc.)"]
    end
    A --> B
    A --> C
    C --> D
    D -->|token validated| E
    B --> E
    E --> F
    E --> G
    E --> H
    F -->|query results| E
    G -->|file writes/reads| E
    H -->|outbound calls| E
    subgraph TB3["Trust boundaries"]
        B -.->|HTTP request (untrusted) .-> E
        D -.->|static secret token (gate) .-> E
        E -.->|file system writes (untrusted name) .-> G
        E -.->|XML parsing (untrusted body) .-> H
        E -.->|pickle loads (untrusted bytes) .-> E
    end
```
**Trust boundaries**:
1. Network → FastAPI router (public and internal).  
2. Internal ops gate (`x-internal-token`).  
3. Dispatch handlers → Filesystem (user‑controlled filenames).  
4. Dispatch handlers → XML parser (untrusted body).  
5. Dispatch handlers → Pickle deserialization (untrusted bytes).  
6. Dispatch handlers → Eval / Jinja2 template rendering (untrusted strings).

---

## Threats (PASTA)
| # | Threat | STRIDE | Trust boundary | Attack path |
|---|--------|--------|----------------|-------------|
| 1 | Deserialization of attacker‑controlled pickle data → Remote Code Execution | **E** (Elevation of privilege) | Dispatch handlers → Pickle loads (boundary 5) | Attacker sends crafted payload to `POST /ops/bundle/dispatch-thaw-172`; `_wrk_gate` validates static token; handler `pickle.loads` executes attacker code → full server compromise |
| 2 | Unsafe `eval` of query parameter → Remote Code Execution | **E** | Dispatch handlers → Eval (boundary 6) | Attacker calls `GET /ops/formula/dispatch-cast-254?expr=<payload>`; after gate passes, `eval` executes arbitrary Python expression |
| 3 | Server‑Side Template Injection via Jinja2 `{{ card|safe }}` | **E** | Dispatch handlers → Jinja2 rendering (boundary 6) | Attacker supplies `card` query param to `GET /ops/blurb/dispatch-tile-320`; template renders raw HTML/JS, leading to XSS or further code execution on downstream consumers |
| 4 | Server‑Side Template Injection via raw fragment concatenation | **E** | Dispatch handlers → Jinja2 rendering (boundary 6) | Attacker supplies `fragment` to `GET /ops/jinja/dispatch-cast-380`; fragment is concatenated into template source, allowing arbitrary template execution |
| 5 | XML External Entity (XXE) injection | **I** (Information disclosure) | Dispatch handlers → XML parser (boundary 4) | Attacker POSTs XML to `POST /ops/xml/dispatch-fold-450`; parser with `load_dtd=True` and `resolve_entities=True` reads external entities, exposing file contents or internal network resources |
| 6 | Open redirect | **R** (Redirection) | Dispatch handlers → RedirectResponse (boundary 1) | Attacker supplies `lane` to `GET /ops/after/dispatch-afterlane-021`; server redirects to attacker‑controlled URL |
| 7 | Reflected CORS origin header | **I** | Dispatch handlers → CORS header (boundary 1) | Attacker sets `Origin` header on `GET /ops/origin/dispatch-mirror-375`; response echoes it, enabling credential‑leakage via malicious site |
| 8 | Unrestricted file write with attacker‑controlled filename | **I** / **E** (Path traversal, arbitrary file write) | Dispatch handlers → Filesystem (boundary 3) | Attacker controls `name` query param on `POST /ops/dock/dispatch-shelf-393`; server writes raw bytes to `BASE_EXPORT_DIR/<name>`, allowing overwrite of arbitrary files if `../` is used |
| 9 | NoSQL injection via raw MongoDB filter | **I** (Data leakage) | Dispatch handlers → MongoDB (boundary 1) | Attacker sends crafted JSON to `POST /ops/mongo/dispatch-lane-415`; filter dict is passed directly to `find_one`, enabling enumeration of arbitrary records |

---

## Hunt targets
```json
[
  {
    "id": "TM-1",
    "subsystem": "Pickle Deserialization",
    "paths": ["backend/app/dispatch_operations.py"],
    "threat": "Remote code execution via unsafe pickle.loads",
    "cwe_class": "CWE-502",
    "priority": "high"
  },
  {
    "id": "TM-2",
    "subsystem": "Eval Execution",
    "paths": ["backend/app/dispatch_operations.py"],
    "threat": "Remote code execution via eval of user‑controlled expression",
    "cwe_class": "CWE-94",
    "priority": "high"
  },
  {
    "id": "TM-3",
    "subsystem": "Template Injection (safe filter)",
    "paths": ["backend/app/dispatch_operations.py"],
    "threat": "Server‑side template injection via Jinja2 safe filter",
    "cwe_class": "CWE-94",
    "priority": "high"
  },
  {
    "id": "TM-4",
    "subsystem": "Template Injection (raw fragment)",
    "paths": ["backend/app/dispatch_operations.py"],
    "threat": "Server‑side template injection via raw fragment concatenation",
    "cwe_class": "CWE-94",
    "priority": "high"
  },
  {
    "id": "TM-5",
    "subsystem": "XXE",
    "paths": ["backend/app/dispatch_operations.py"],
    "threat": "XML external entity injection",
    "cwe_class": "CWE-611",
    "priority": "high"
  },
  {
    "id": "TM-6",
    "subsystem": "Open Redirect",
    "paths": ["backend/app/dispatch_operations.py"],
    "threat": "Open redirect via uncontrolled lane parameter",
    "cwe_class": "CWE-601",
    "priority": "medium"
  },
  {
    "id": "TM-7",
    "subsystem": "CORS Reflection",
    "paths": ["backend/app/dispatch_operations.py"],
    "threat": "Reflected Origin header leading to credential leakage",
    "cwe_class": "CWE-942",
    "priority": "medium"
  },
  {
    "id": "TM-8",
    "subsystem": "File Write / Path Traversal",
    "paths": ["backend/app/dispatch_operations.py"],
    "threat": "Arbitrary file write via uncontrolled filename",
    "cwe_class": "CWE-22",
    "priority": "high"
  },
  {
    "id": "TM-9",
    "subsystem": "MongoDB NoSQL Injection",
    "paths": ["backend/app/dispatch_operations.py"],
    "threat": "Information disclosure via raw MongoDB filter",
    "cwe_class": "CWE-20",
    "priority": "medium"
  }
]
```
