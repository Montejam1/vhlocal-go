```mermaid
flowchart TD
    subgraph TB1["Attacker"]
        B["Browser"]
    end
    subgraph TB2["Application"]
        E["Router"]
    end
    subgraph TB3["Trust boundaries"]
        B -.->|HTTP request (untrusted) .-> E
    end
```
