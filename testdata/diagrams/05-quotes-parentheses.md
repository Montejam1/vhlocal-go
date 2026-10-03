```mermaid
flowchart TD
    A["Attacker (HTTP/gRPC)" ]
    B["Router (/ops/*) - internal ops"]
    A -->|"POST /ops/export (csv)"| B
```
