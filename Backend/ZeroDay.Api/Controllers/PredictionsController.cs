using System.Security.Claims;
using System.Text.Json;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using ZeroDay.Api.Data;
using ZeroDay.Api.Models;
using ZeroDay.Api.Services;

namespace ZeroDay.Api.Controllers;

[ApiController]
[Authorize]
public class PredictionsController : ControllerBase
{
    private readonly ApplicationDbContext _db;
    private readonly DatasetService _datasets;
    private readonly PredictionService _predictions;
    private readonly IAuditService _audit;

    public PredictionsController(ApplicationDbContext db, DatasetService datasets, PredictionService predictions, IAuditService audit)
    { _db = db; _datasets = datasets; _predictions = predictions; _audit = audit; }

    private string UserId => User.FindFirstValue(ClaimTypes.NameIdentifier)!;

    public class PredictForm
    {
        public IFormFile? File { get; set; }
        public int? DatasetId { get; set; }
        public string? Name { get; set; }
    }

    /// <summary>Upload a CSV (field "file") or reference an existing dataset ("datasetId"), then analyse it.</summary>
    [HttpPost("predict")]
    [Authorize(Roles = Roles.AnalystOrAdmin)]
    [RequestSizeLimit(250_000_000)]
    [RequestFormLimits(MultipartBodyLengthLimit = 250_000_000)]
    public async Task<IActionResult> Predict([FromForm] PredictForm form, CancellationToken ct)
    {
        Dataset? ds;
        try
        {
            if (form.File != null)
            {
                ds = await _datasets.UploadAsync(form.File, form.Name, UserId, ct);
                await _audit.LogAsync("DatasetUpload", "Dataset", ds.Id.ToString(), $"{ds.OriginalFileName} via /predict");
            }
            else if (form.DatasetId.HasValue)
                ds = await _db.Datasets.FirstOrDefaultAsync(d => d.Id == form.DatasetId.Value, ct);
            else
                return BadRequest(new { error = "Provide a CSV in form field 'file' or an existing 'datasetId'." });
        }
        catch (ArgumentException ex) { return BadRequest(new { error = ex.Message }); }

        if (ds == null) return NotFound(new { error = "Dataset not found." });
        if (ds.Status != "Validated") return UnprocessableEntity(new { error = "Dataset failed validation.", detail = ds.ValidationMessage });

        try
        {
            var p = await _predictions.RunAsync(ds, UserId, ct);
            await _audit.LogAsync("Prediction", "Prediction", p.Id.ToString(),
                $"dataset {ds.Id}: {p.TotalFlows} flows, {p.ThreatCount} threats, {p.ZeroDayCount} zero-day");

            var top = await _db.Threats.AsNoTracking().Where(t => t.PredictionId == p.Id)
                        .OrderByDescending(t => t.RiskScore).Take(20).ToListAsync(ct);
            var best = top.FirstOrDefault();
            return Ok(new
            {
                predictionId = p.Id,
                datasetId = ds.Id,
                // headline result in the format requested by the project brief
                result = best == null
                    ? new { riskScore = 0, threatType = "Benign", severity = "Low", confidence = "100%" }
                    : new { riskScore = best.RiskScore, threatType = best.ThreatType, severity = best.Severity,
                            confidence = (await _db.RiskScores.Where(r => r.PredictionId == p.Id && r.FlowIndex == best.FlowIndex)
                                          .Select(r => r.Confidence).FirstOrDefaultAsync(ct)) + "%" },
                summary = Summary(p),
                topThreats = top.Select(ThreatDto)
            });
        }
        catch (MlServiceException ex) { return StatusCode(502, new { error = ex.Message }); }
        catch (HttpRequestException ex) { return StatusCode(503, new { error = "ML service unreachable: " + ex.Message }); }
        catch (TaskCanceledException) when (!ct.IsCancellationRequested) { return StatusCode(504, new { error = "ML service timed out." }); }
        catch (InvalidOperationException ex) { return UnprocessableEntity(new { error = ex.Message }); }
        catch (FileNotFoundException ex) { return NotFound(new { error = ex.Message }); }
    }

    [HttpGet("predictions")]
    public async Task<IActionResult> List([FromQuery] int page = 1, [FromQuery] int pageSize = 20)
    {
        pageSize = Math.Clamp(pageSize, 1, 100); page = Math.Max(page, 1);
        var q = _db.Predictions.AsNoTracking().Include(p => p.Dataset).OrderByDescending(p => p.CreatedAt);
        var total = await q.CountAsync();
        var items = await q.Skip((page - 1) * pageSize).Take(pageSize).ToListAsync();
        return Ok(new { total, page, pageSize, items = items.Select(p => new { p.Id, dataset = p.Dataset!.Name, summary = Summary(p), p.CreatedAt }) });
    }

    [HttpGet("predictions/{id:int}")]
    public async Task<IActionResult> Get(int id)
    {
        var p = await _db.Predictions.AsNoTracking().Include(x => x.Dataset).FirstOrDefaultAsync(x => x.Id == id);
        return p == null ? NotFound() : Ok(new { p.Id, p.DatasetId, dataset = p.Dataset!.Name, summary = Summary(p), p.CreatedAt });
    }

    internal static object Summary(Prediction p) => new
    {
        p.TotalFlows, threats = p.ThreatCount, zeroDayDetections = p.ZeroDayCount, highRiskAlerts = p.HighRiskCount,
        p.MeanRisk, threshold = p.Threshold, blendWeight = p.BlendWeight, p.StoredThreats, p.Truncated, p.DurationMs,
        byThreatType = JsonSerializer.Deserialize<Dictionary<string, int>>(p.ThreatTypeCountsJson),
        riskHistogram = JsonSerializer.Deserialize<int[]>(p.RiskHistogramJson)
    };

    internal static object ThreatDto(Threat t) => new
    {
        t.Id, t.PredictionId, t.FlowIndex, t.ThreatType, t.Severity, t.RiskScore, t.AnomalyScore,
        t.SupervisedProbability, t.Description, t.DetectedAt
    };
}
