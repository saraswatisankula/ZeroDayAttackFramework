using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using QuestPDF.Fluent;
using QuestPDF.Helpers;
using QuestPDF.Infrastructure;
using ZeroDay.Api.Data;
using ZeroDay.Api.Models;

namespace ZeroDay.Api.Services;

public class ReportService
{
    private readonly ApplicationDbContext _db;
    public ReportService(ApplicationDbContext db) { _db = db; QuestPDF.Settings.License = LicenseType.Community; }

    public async Task<Report> CreateAsync(int predictionId, string type, string userId, CancellationToken ct)
    {
        var p = await _db.Predictions.Include(x => x.Dataset).FirstOrDefaultAsync(x => x.Id == predictionId, ct)
                ?? throw new KeyNotFoundException("Prediction not found.");
        var top = await _db.Threats.Where(t => t.PredictionId == predictionId)
                    .OrderByDescending(t => t.RiskScore).Take(50)
                    .Select(t => new { t.FlowIndex, t.ThreatType, t.Severity, t.RiskScore, t.AnomalyScore, t.SupervisedProbability })
                    .ToListAsync(ct);
        var sev = await _db.Threats.Where(t => t.PredictionId == predictionId)
                    .GroupBy(t => t.Severity).Select(g => new { g.Key, N = g.Count() }).ToListAsync(ct);

        object content = type == "Risk"
            ? new
            {
                dataset = p.Dataset!.Name, generatedAt = DateTime.UtcNow, totalFlows = p.TotalFlows, meanRisk = p.MeanRisk,
                highRiskFlows = p.HighRiskCount, riskHistogram = JsonSerializer.Deserialize<int[]>(p.RiskHistogramJson),
                severityBreakdown = sev.ToDictionary(s => s.Key, s => s.N), threshold = p.Threshold, topFlows = top.Take(20)
            }
            : new
            {
                dataset = p.Dataset!.Name, generatedAt = DateTime.UtcNow, totalFlows = p.TotalFlows, threats = p.ThreatCount,
                zeroDay = p.ZeroDayCount, byType = JsonSerializer.Deserialize<Dictionary<string, int>>(p.ThreatTypeCountsJson),
                severityBreakdown = sev.ToDictionary(s => s.Key, s => s.N), truncated = p.Truncated, topThreats = top
            };

        var r = new Report
        {
            Type = type,
            Title = $"{type} report - {p.Dataset!.Name} - {DateTime.UtcNow:yyyy-MM-dd HH:mm} UTC",
            PredictionId = predictionId,
            GeneratedByUserId = userId,
            ContentJson = JsonSerializer.Serialize(content, new JsonSerializerOptions(JsonSerializerDefaults.Web)),
            CreatedAt = DateTime.UtcNow
        };
        _db.Reports.Add(r);
        await _db.SaveChangesAsync(ct);
        return r;
    }

    public byte[] ToPdf(Report r)
    {
        using var doc = JsonDocument.Parse(r.ContentJson);
        var root = doc.RootElement;
        string S(string name) => root.TryGetProperty(name, out var v) ? v.ToString() : "-";
        var rows = new List<(string, string, string, string)>();
        string listKey = r.Type == "Risk" ? "topFlows" : "topThreats";
        if (root.TryGetProperty(listKey, out var arr))
            foreach (var t in arr.EnumerateArray())
                rows.Add((t.GetProperty("flowIndex").ToString(), t.GetProperty("threatType").GetString() ?? "",
                          t.GetProperty("severity").GetString() ?? "", t.GetProperty("riskScore").ToString()));

        return Document.Create(c => c.Page(p =>
        {
            p.Size(PageSizes.A4);
            p.Margin(30);
            p.DefaultTextStyle(x => x.FontSize(10));
            p.Header().Text(r.Title).FontSize(16).Bold();
            p.Content().PaddingVertical(10).Column(col =>
            {
                col.Spacing(6);
                col.Item().Text($"Dataset: {S("dataset")}    Flows analysed: {S("totalFlows")}");
                if (r.Type == "Risk")
                    col.Item().Text($"Mean risk: {S("meanRisk")}    High-risk flows: {S("highRiskFlows")}    Threshold: {S("threshold")}");
                else
                    col.Item().Text($"Threats: {S("threats")}    Zero-day detections: {S("zeroDay")}");
                if (root.TryGetProperty("severityBreakdown", out var sb))
                    col.Item().Text("Severity: " + string.Join(", ", sb.EnumerateObject().Select(o => $"{o.Name}={o.Value}")));
                col.Item().PaddingTop(8).Text(r.Type == "Risk" ? "Highest-risk flows" : "Top threats").Bold();
                col.Item().Table(t =>
                {
                    t.ColumnsDefinition(cd => { cd.ConstantColumn(60); cd.RelativeColumn(); cd.ConstantColumn(80); cd.ConstantColumn(60); });
                    t.Header(h =>
                    {
                        foreach (var head in new[] { "Flow", "Type", "Severity", "Risk" })
                            h.Cell().Background(Colors.Grey.Lighten2).Padding(3).Text(head).Bold();
                    });
                    foreach (var (f, ty, sv, rk) in rows)
                    {
                        t.Cell().BorderBottom(0.5f).Padding(3).Text(f);
                        t.Cell().BorderBottom(0.5f).Padding(3).Text(ty);
                        t.Cell().BorderBottom(0.5f).Padding(3).Text(sv);
                        t.Cell().BorderBottom(0.5f).Padding(3).Text(rk);
                    }
                });
            });
            p.Footer().AlignCenter().Text(x => { x.Span("Zero-Day Attack Framework - page "); x.CurrentPageNumber(); });
        })).GeneratePdf();
    }
}
