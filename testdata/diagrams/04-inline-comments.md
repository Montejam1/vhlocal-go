```mermaid
flowchart LR
    %% Trust boundaries
    E["API"] --> F["DB"]   %% ORM queries
    F --> G["Cache"]
```
