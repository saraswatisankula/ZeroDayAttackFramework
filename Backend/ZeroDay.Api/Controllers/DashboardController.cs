using System.Text.Json;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using ZeroDay.Api.Data;
using ZeroDay.Api.Services;

namespace ZeroDay.Api.Controllers;

[ApiController]
[Authorize]
public class DashboardController : ControllerBase
{
    private readonly ApplicationDbContext _db;
    private readonly MlClient _ml;
    public DashboardController(ApplicationDbContext db, MlClient ml) { _db = db; _ml = ml; }

    [HttpGet("dashboard/summary")]
    public async Task<IActionResult> Summary([FromQuery] int days = 30, CancellationToken ct = default)
    {
        days = Math.Clamp(days, 1, 365);
        var since = DateTime.UtcNow.Date.AddDays(-days + 1);

        var preds = await _db.Predictions.AsNoTracking().Where(p => p.CreatedAt >= since)
            .Select(p => new { p.CreatedAt, p.TotalFlows, p.ThreatCount, p.ZeroDayCount, p.HighRiskCount, p.RiskHistogramJson, p.ThreatTypeCountsJson })
            .ToListAsync(ct);

        var dist = new Dictionary<string, int>();
        var hist = new int[10];
        foreach (var p in preds)
        {
            foreach (var kv in JsonSerializer.Deserialize<Dictionary<string, int>>(p.ThreatTypeCountsJson) ?? new())
                dist[kv.Key] = dist.GetValueOrDefault(kv.Key) + kv.Value;
            var h = JsonSerializer.Deserialize<int[]>(p.RiskHistogramJson) ?? new int[10];
            for (int i = 0; i < Math.Min(10, h.Length); i++) hist[i] += h[i];
        }

        var trend = Enumerable.Range(0, days).Select(i => since.AddDays(i)).Select(day => new
        {
            date = day.ToString("yyyy-MM-dd"),
            flows = preds.Where(p => p.CreatedAt.Date == day).Sum(p => p.TotalFlows),
            threats = preds.Where(p => p.CreatedAt.Date == day).Sum(p => p.ThreatCount),
            zeroDay = preds.Where(p => p.CreatedAt.Date == day).Sum(p => p.ZeroDayCount)
        });

        var openAlerts = await _db.Alerts.CountAsync(a => a.Status == "Open", ct);
        var health = await _ml.HealthAsync(ct);

        return Ok(new
        {
            windowDays = days,
            totals = new
            {
                totalNetworkFlows = preds.Sum(p => p.TotalFlows),
                totalThreats = preds.Sum(p => p.ThreatCount),
                highRiskAlerts = preds.Sum(p => p.HighRiskCount),
                zeroDayDetections = preds.Sum(p => p.ZeroDayCount),
                openAlerts,
                datasets = await _db.Datasets.CountAsync(ct),
                analyses = preds.Count
            },
            threatDistribution = dist,
            riskAnalysis = Enumerable.Range(0, 10).Select(i => new { bucket = $"{i * 10}-{i * 10 + 9}", count = hist[i] }),
            detectionTrends = trend,
            modelPerformance = health,    // metrics reported by the ML service for the trained model (null if the service is down)
            recentAlerts = await _db.Alerts.AsNoTracking().Include(a => a.Threat).OrderByDescending(a => a.CreatedAt).Take(8)
                .Select(a => new { a.Id, a.Title, a.Severity, a.Status, a.CreatedAt, riskScore = a.Threat!.RiskScore }).ToListAsync(ct)
        });
    }
}
