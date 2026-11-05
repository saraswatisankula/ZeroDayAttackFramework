# Zero-Day Attack Framework Using ML-Based Anomaly Detection

| Folder | Content | Verified? |
|---|---|---|
| `ML/` | Python pipeline: 6 models, hybrid Isolation Forest + XGBoost, risk scoring, FastAPI service | run end-to-end on synthetic data only |
| `Database/` | `schema.sql` (SQL Server), `ER_Diagram.md` | not executed against SQL Server |
| `Backend/ZeroDay.Api` | ASP.NET Core 8 REST API, EF Core, Identity, JWT, PDF reports | NOT compiled |
| `Frontend/ZeroDay.Web` | ASP.NET Core 8 MVC site: Bootstrap 5, Chart.js | NOT compiled |
| `Deployment/` | `docker-compose.yml`, `.env.example`, scripts; `render.yaml` also at repo root | NOT run |
| `Documentation/` | `API_Reference.md`, `DEPLOYMENT_GUIDE.md` | - |

Start with `Documentation/DEPLOYMENT_GUIDE.md` section 1.
No experiment results exist yet: run `ML/model_compare.py` on real CIC-IDS2017 data before writing any numbers into a report.
Still to do: IEEE report, 15-slide PPT, 50 viva Q&A (these need your real results).
