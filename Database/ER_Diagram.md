# Entity-Relationship Diagram

Render with any Mermaid viewer (GitHub, VS Code "Markdown Preview Mermaid Support", https://mermaid.live).

```mermaid
erDiagram
    Users ||--o{ UserRoles : has
    Roles ||--o{ UserRoles : grants
    Users ||--o{ Datasets : uploads
    Users ||--o{ Predictions : runs
    Users ||--o{ Reports : generates
    Users ||--o{ AuditLogs : performs
    Users ||--o{ Alerts : acknowledges
    Datasets ||--o{ NetworkTraffic : contains
    Datasets ||--o{ Predictions : analysed_by
    Predictions ||--o{ RiskScores : scores
    Predictions ||--o{ Threats : detects
    Predictions |o--o{ Reports : summarised_in
    Threats ||--o{ Alerts : raises

    Users { string Id PK
            string Email
            string FullName
            bool IsActive
            datetime CreatedAt }
    Roles { string Id PK
            string Name }
    Datasets { int Id PK
               string Name
               int RowCount
               int ColumnCount
               string Status
               string UploadedByUserId FK }
    NetworkTraffic { bigint Id PK
                     int DatasetId FK
                     int FlowIndex
                     float FlowDuration
                     float FlowBytesPerSec }
    Predictions { int Id PK
                  int DatasetId FK
                  string UserId FK
                  int TotalFlows
                  int ThreatCount
                  int ZeroDayCount
                  float Threshold }
    RiskScores { bigint Id PK
                 int PredictionId FK
                 int FlowIndex
                 int Score
                 string Severity }
    Threats { bigint Id PK
              int PredictionId FK
              int FlowIndex
              string ThreatType
              string Severity
              int RiskScore }
    Alerts { bigint Id PK
             bigint ThreatId FK
             string Status
             string Severity
             string AcknowledgedByUserId FK }
    Reports { int Id PK
              string Type
              int PredictionId FK
              string GeneratedByUserId FK }
    AuditLogs { bigint Id PK
                string UserId FK
                string Action
                datetime Timestamp }
```

Design notes
- `NetworkTraffic` is linked logically to `Threats`/`RiskScores` through (Prediction.DatasetId, FlowIndex); no direct FK, which avoids SQL Server multiple-cascade-path errors.
- Delete cascade: Dataset -> NetworkTraffic, Predictions -> (RiskScores, Threats -> Alerts). Reports survive prediction deletion (`SET NULL`). Audit logs survive user deletion (`SET NULL`).
