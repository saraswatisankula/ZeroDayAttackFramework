using System.Security.Claims;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using ZeroDay.Api.Data;
using ZeroDay.Api.Dtos;
using ZeroDay.Api.Models;
using ZeroDay.Api.Services;

namespace ZeroDay.Api.Controllers;

[ApiController]
[Authorize]
public class ThreatsController : ControllerBase
{
    private readonly ApplicationDbContext _db;
    public ThreatsController(ApplicationDbContext db) => _db = db;

    [HttpGet("threats")]
    public async Task<IActionResult> List([FromQuery] int? predictionId, [FromQuery] string? severity, [FromQuery] string? type,
                                          [FromQuery] int? minRisk, [FromQuery] int page = 1, [FromQuery] int pageSize = 50)
    {
        pageSize = Math.Clamp(pageSize, 1, 200); page = Math.Max(page, 1);
        var q = _db.Threats.AsNoTracking().AsQueryable();
        if (predictionId.HasValue) q = q.Where(t => t.PredictionId == predictionId);
        if (!string.IsNullOrWhiteSpace(severity)) q = q.Where(t => t.Severity == severity);
        if (!string.IsNullOrWhiteSpace(type)) q = q.Where(t => t.ThreatType == type);
        if (minRisk.HasValue) q = q.Where(t => t.RiskScore >= minRisk);
        var total = await q.CountAsync();
        var items = await q.OrderByDescending(t => t.RiskScore).ThenByDescending(t => t.DetectedAt)
                           .Skip((page - 1) * pageSize).Take(pageSize).ToListAsync();
        return Ok(new { total, page, pageSize, items = items.Select(PredictionsController.ThreatDto) });
    }
}

[ApiController]
[Authorize]
public class AlertsController : ControllerBase
{
    private static readonly string[] Allowed = { "Open", "Acknowledged", "Resolved" };
    private readonly ApplicationDbContext _db;
    private readonly IAuditService _audit;
    public AlertsController(ApplicationDbContext db, IAuditService audit) { _db = db; _audit = audit; }

    [HttpGet("alerts")]
    public async Task<IActionResult> List([FromQuery] string? status, [FromQuery] string? severity,
                                          [FromQuery] int page = 1, [FromQuery] int pageSize = 50)
    {
        pageSize = Math.Clamp(pageSize, 1, 200); page = Math.Max(page, 1);
        var q = _db.Alerts.AsNoTracking().Include(a => a.Threat).AsQueryable();
        if (!string.IsNullOrWhiteSpace(status)) q = q.Where(a => a.Status == status);
        if (!string.IsNullOrWhiteSpace(severity)) q = q.Where(a => a.Severity == severity);
        var total = await q.CountAsync();
        var items = await q.OrderByDescending(a => a.CreatedAt).ThenByDescending(a => a.Threat!.RiskScore)
                           .Skip((page - 1) * pageSize).Take(pageSize)
                           .Select(a => new
                           {
                               a.Id, a.Title, a.Severity, a.Status, a.CreatedAt, a.AcknowledgedAt,
                               threatId = a.ThreatId, threatType = a.Threat!.ThreatType, riskScore = a.Threat.RiskScore,
                               predictionId = a.Threat.PredictionId, flowIndex = a.Threat.FlowIndex
                           }).ToListAsync();
        return Ok(new { total, page, pageSize, items });
    }

    [HttpPut("alerts/{id:long}/status")]
    [Authorize(Roles = Roles.AnalystOrAdmin)]
    public async Task<IActionResult> SetStatus(long id, [FromBody] UpdateAlertStatusRequest req)
    {
        if (!Allowed.Contains(req.Status)) return BadRequest(new { error = "Status must be Open, Acknowledged or Resolved." });
        var a = await _db.Alerts.FirstOrDefaultAsync(x => x.Id == id);
        if (a == null) return NotFound();
        a.Status = req.Status;
        if (req.Status != "Open")
        {
            a.AcknowledgedAt = DateTime.UtcNow;
            a.AcknowledgedByUserId = User.FindFirstValue(ClaimTypes.NameIdentifier);
        }
        await _db.SaveChangesAsync();
        await _audit.LogAsync("AlertStatusChanged", "Alert", id.ToString(), req.Status);
        return Ok(new { a.Id, a.Status, a.AcknowledgedAt });
    }
}

[ApiController]
[Authorize]
public class ReportsController : ControllerBase
{
    private readonly ApplicationDbContext _db;
    private readonly ReportService _svc;
    private readonly IAuditService _audit;
    public ReportsController(ApplicationDbContext db, ReportService svc, IAuditService audit) { _db = db; _svc = svc; _audit = audit; }

    [HttpGet("reports")]
    public async Task<IActionResult> List([FromQuery] int page = 1, [FromQuery] int pageSize = 20)
    {
        pageSize = Math.Clamp(pageSize, 1, 100); page = Math.Max(page, 1);
        var q = _db.Reports.AsNoTracking().OrderByDescending(r => r.CreatedAt);
        var total = await q.CountAsync();
        var items = await q.Skip((page - 1) * pageSize).Take(pageSize)
                           .Select(r => new { r.Id, r.Type, r.Title, r.PredictionId, r.CreatedAt }).ToListAsync();
        return Ok(new { total, page, pageSize, items });
    }

    [HttpGet("reports/{id:int}")]
    public async Task<IActionResult> Get(int id)
    {
        var r = await _db.Reports.AsNoTracking().FirstOrDefaultAsync(x => x.Id == id);
        if (r == null) return NotFound();
        return Ok(new { r.Id, r.Type, r.Title, r.PredictionId, r.CreatedAt, content = System.Text.Json.JsonSerializer.Deserialize<System.Text.Json.JsonElement>(r.ContentJson) });
    }

    [HttpPost("reports")]
    [Authorize(Roles = Roles.AnalystOrAdmin)]
    public async Task<IActionResult> Create([FromBody] CreateReportRequest req, CancellationToken ct)
    {
        if (req.Type is not ("Threat" or "Risk")) return BadRequest(new { error = "Type must be 'Threat' or 'Risk'." });
        try
        {
            var r = await _svc.CreateAsync(req.PredictionId, req.Type, User.FindFirstValue(ClaimTypes.NameIdentifier)!, ct);
            await _audit.LogAsync("ReportGenerated", "Report", r.Id.ToString(), r.Title);
            return CreatedAtAction(nameof(Get), new { id = r.Id }, new { r.Id, r.Type, r.Title, r.PredictionId, r.CreatedAt });
        }
        catch (KeyNotFoundException ex) { return NotFound(new { error = ex.Message }); }
    }

    [HttpGet("reports/{id:int}/pdf")]
    public async Task<IActionResult> Pdf(int id)
    {
        var r = await _db.Reports.AsNoTracking().FirstOrDefaultAsync(x => x.Id == id);
        if (r == null) return NotFound();
        await _audit.LogAsync("ReportExportPdf", "Report", id.ToString());
        return File(_svc.ToPdf(r), "application/pdf", $"report-{id}.pdf");
    }
}

[ApiController]
[Authorize(Roles = Roles.Admin)]
public class AuditLogsController : ControllerBase
{
    private readonly ApplicationDbContext _db;
    public AuditLogsController(ApplicationDbContext db) => _db = db;

    [HttpGet("audit-logs")]
    public async Task<IActionResult> List([FromQuery] string? action, [FromQuery] string? email, [FromQuery(Name = "from")] DateTime? fromDate,
                                          [FromQuery(Name = "to")] DateTime? toDate, [FromQuery] int page = 1, [FromQuery] int pageSize = 50)
    {
        pageSize = Math.Clamp(pageSize, 1, 200); page = Math.Max(page, 1);
        var q = _db.AuditLogs.AsNoTracking().AsQueryable();
        if (!string.IsNullOrWhiteSpace(action)) q = q.Where(a => a.Action == action);
        if (!string.IsNullOrWhiteSpace(email)) q = q.Where(a => a.UserEmail != null && a.UserEmail.Contains(email));
        if (fromDate.HasValue) q = q.Where(a => a.Timestamp >= fromDate);
        if (toDate.HasValue) q = q.Where(a => a.Timestamp <= toDate);
        var total = await q.CountAsync();
        var items = await q.OrderByDescending(a => a.Timestamp).Skip((page - 1) * pageSize).Take(pageSize).ToListAsync();
        return Ok(new { total, page, pageSize, items });
    }
}
