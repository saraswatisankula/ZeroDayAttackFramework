using System.Diagnostics;
using System.Text.Json;
using ZeroDay.Api.Data;
using ZeroDay.Api.Models;

namespace ZeroDay.Api.Services;

public class PredictionService
{
    private readonly ApplicationDbContext _db;
    private readonly MlClient _ml;
    private readonly IConfiguration _cfg;

    public PredictionService(ApplicationDbContext db, MlClient ml, IConfiguration cfg) { _db = db; _ml = ml; _cfg = cfg; }

    public async Task<Prediction> RunAsync(Dataset ds, string userId, CancellationToken ct)
    {
        if (ds.Status != "Validated") throw new InvalidOperationException("Dataset failed validation and cannot be analysed.");
        if (!File.Exists(ds.StoragePath)) throw new FileNotFoundException("Dataset file is no longer on the server; please upload it again.");

        int maxRows = _cfg.GetValue<int?>("Ml:MaxRows") ?? 50000;
        int maxStored = _cfg.GetValue<int?>("Upload:MaxStoredThreats") ?? 5000;
        const int maxAlerts = 1000;

        var sw = Stopwatch.StartNew();
        var ml = await _ml.PredictAsync(ds.StoragePath, ds.OriginalFileName, maxRows, ct);
        sw.Stop();

        var hist = new int[10];
        foreach (var r in ml.Results) hist[Math.Clamp(r.RiskScore / 10, 0, 9)]++;

        var threatsAll = ml.Results.Where(r => r.ThreatType != "Benign").OrderByDescending(r => r.RiskScore).ToList();
        var stored = threatsAll.Take(maxStored).ToList();

        var pred = new Prediction
        {
            DatasetId = ds.Id,
            UserId = userId,
            TotalFlows = ml.Summary.TotalFlows,
            ThreatCount = ml.Summary.Threats,
            ZeroDayCount = ml.Summary.ZeroDayDetections,
            HighRiskCount = ml.Summary.HighRiskAlerts,
            MeanRisk = ml.Results.Count == 0 ? 0 : Math.Round(ml.Results.Average(r => r.RiskScore), 2),
            RiskHistogramJson = JsonSerializer.Serialize(hist),
            ThreatTypeCountsJson = JsonSerializer.Serialize(ml.Summary.ByThreatType),
            Threshold = ml.Summary.Threshold,
            BlendWeight = ml.Summary.BlendWeight,
            StoredThreats = stored.Count,
            Truncated = threatsAll.Count > stored.Count,
            DurationMs = (int)sw.ElapsedMilliseconds,
            CreatedAt = DateTime.UtcNow
        };

        int alerts = 0;
        foreach (var r in stored)
        {
            int conf = int.TryParse(r.Confidence.TrimEnd('%'), out var cf) ? cf : 0;
            pred.RiskScores.Add(new RiskScore
            {
                FlowIndex = r.FlowId, Score = r.RiskScore, Severity = r.Severity,
                AnomalyScore = r.AnomalyScore, SupervisedProbability = r.SupervisedProbability, Confidence = conf
            });
            var threat = new Threat
            {
                FlowIndex = r.FlowId, ThreatType = r.ThreatType, Severity = r.Severity, RiskScore = r.RiskScore,
                AnomalyScore = r.AnomalyScore, SupervisedProbability = r.SupervisedProbability,
                Description = $"Flow #{r.FlowId}: {r.ThreatType}, risk {r.RiskScore}/100, anomaly {r.AnomalyScore:P0}, known-attack probability {r.SupervisedProbability:P0}.",
                DetectedAt = pred.CreatedAt
            };
            bool alertWorthy = r.Severity is "High" or "Critical" || r.ThreatType == "Zero-Day Attack";
            if (alertWorthy && alerts < maxAlerts)
            {
                threat.Alerts.Add(new Alert
                {
                    Title = $"{r.Severity} {r.ThreatType} (flow #{r.FlowId})",
                    Severity = r.Severity, Status = "Open", CreatedAt = pred.CreatedAt
                });
                alerts++;
            }
            pred.Threats.Add(threat);
        }

        _db.Predictions.Add(pred);
        await _db.SaveChangesAsync(ct);
        return pred;
    }
}
