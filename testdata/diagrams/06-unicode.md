```mermaid
flowchart TD
    C["FastAPI router (/ops/*) – internal ops"]
    D["Internal Ops Gate (x‑internal‑token) "]
    C -->|HTTP → Application| D
```
