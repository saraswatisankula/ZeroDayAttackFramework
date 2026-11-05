# REST API Reference

Base URL (local): `http://localhost:8080`. Interactive docs: `/swagger`.
All endpoints except `/register`, `/login`, `/forgot-password`, `/reset-password`, `/health` need
`Authorization: Bearer <token>`. Roles: **Admin** (everything), **Analyst** (upload, predict, alerts, reports),
**Viewer** (read-only). Data is organisation-wide (SOC model): every role reads all datasets/threats/alerts.

## Authentication
### POST /register
```json
{ "email": "analyst@uni.edu", "password": "Strong#Pass1", "fullName": "A. Analyst" }
```
201-style success (200):
```json
{ "token": "eyJhbGciOi...", "expiresAt": "2026-11-05T12:00:00Z", "email": "analyst@uni.edu",
  "fullName": "A. Analyst", "roles": ["Analyst"] }
```
Errors: `400 {"error":"Registration failed.","details":["Passwords must have at least one uppercase ('A'-'Z')."]}`

### POST /login
```json
{ "email": "analyst@uni.edu", "password": "Strong#Pass1" }
```
Same response as /register. `401 {"error":"Invalid email or password."}`; `423` after 5 failures (15 min lockout).

### POST /forgot-password  /  POST /reset-password
```json
{ "email": "analyst@uni.edu" }
{ "email": "analyst@uni.edu", "token": "<reset token>", "newPassword": "NewStrong#Pass2" }
```
The token is only returned in the response when `Auth__ReturnResetToken=true` (development). In production wire an
email provider into `AuthController.Forgot`.

## Datasets
### POST /upload  (Analyst, Admin) - multipart/form-data
`curl -H "Authorization: Bearer $T" -F "file=@Monday-WorkingHours.pcap_ISCX.csv" -F "name=Monday" http://localhost:8080/upload`
```json
{ "id": 7, "name": "Monday", "originalFileName": "Monday-WorkingHours.pcap_ISCX.csv", "sizeBytes": 168186,
  "rowCount": 529918, "columnCount": 79, "hasLabelColumn": true, "status": "Validated",
  "validationMessage": "Duplicate column names: Fwd Header Length.", "uploadedAt": "2026-11-04T09:30:00Z" }
```
`status` is `Validated` or `Invalid` (reason in `validationMessage`). Invalid datasets cannot be analysed.

### GET /datasets?page=1&pageSize=20
```json
{ "total": 1, "page": 1, "pageSize": 20, "items": [ { "id": 7, "name": "Monday", "status": "Validated", "rowCount": 529918 } ] }
```
Also: `GET /datasets/{id}`, `GET /datasets/{id}/preview?rows=20`, `GET /datasets/{id}/stats`, `DELETE /datasets/{id}` (Admin).

## Prediction
### POST /predict  (Analyst, Admin) - multipart/form-data
Send `file` (CSV) **or** `datasetId`.
```json
{
  "predictionId": 12, "datasetId": 7,
  "result": { "riskScore": 96, "threatType": "Zero-Day Attack", "severity": "Critical", "confidence": "98%" },
  "summary": { "totalFlows": 50000, "threats": 4120, "zeroDayDetections": 310, "highRiskAlerts": 2890,
               "meanRisk": 21.4, "threshold": 0.3406, "blendWeight": 0.6, "storedThreats": 4120, "truncated": false,
               "durationMs": 8421, "byThreatType": { "Benign": 45880, "Known Attack": 3500, "Zero-Day Attack": 310, "Suspicious Anomaly": 310 },
               "riskHistogram": [31000, 9000, 4000, 2000, 1500, 900, 700, 500, 250, 150] },
  "topThreats": [ { "id": 901, "flowIndex": 218, "threatType": "Zero-Day Attack", "severity": "Critical", "riskScore": 96,
                    "anomalyScore": 0.9981, "supervisedProbability": 0.12, "description": "Flow #218: ..." } ]
}
```
`result` is the highest-risk flow, in the format of the project brief. `confidence` is a decision-margin percentage, not a calibrated probability.
Errors: `400` bad file, `422` dataset invalid, `502` ML service error, `503` ML service unreachable, `504` ML timeout.
Also `GET /predictions`, `GET /predictions/{id}`.

## Threats, Alerts, Reports, Audit
- `GET /threats?predictionId=12&severity=Critical&type=Zero-Day Attack&minRisk=70&page=1&pageSize=50`
- `GET /alerts?status=Open&severity=High` -> `{ total, items: [{ id, title, severity, status, riskScore, threatType, predictionId, flowIndex }] }`
- `PUT /alerts/{id}/status` body `{ "status": "Acknowledged" }` (Open | Acknowledged | Resolved)
- `GET /reports`, `POST /reports` body `{ "predictionId": 12, "type": "Threat" }` (type: Threat | Risk), `GET /reports/{id}`, `GET /reports/{id}/pdf`
- `GET /audit-logs?action=DatasetUpload&email=analyst&from=2026-11-01&page=1` (Admin)
- `GET /dashboard/summary?days=30` -> totals, threatDistribution, riskAnalysis, detectionTrends, modelPerformance, recentAlerts
- Admin: `GET /admin/users`, `GET /admin/roles`, `PUT /admin/users/{id}/role` body `{ "role": "Viewer" }`, `PUT /admin/users/{id}/active?value=false`
- `GET /health` -> `{ "status": "ok", "database": true }`

## Configuration (environment variables, `__` = nesting)
`ConnectionStrings__Default`, `Jwt__Key` (>=32 chars, required), `Jwt__Issuer`, `Jwt__Audience`, `Ml__BaseUrl`, `Ml__ApiKey`,
`Seed__AdminEmail`, `Seed__AdminPassword`, `Database__AutoCreate`, `Upload__Path`, `Auth__ReturnResetToken`, `Cors__Origins__0`.
