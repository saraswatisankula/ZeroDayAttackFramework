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
public class DatasetsController : ControllerBase
{
    private readonly ApplicationDbContext _db;
    private readonly DatasetService _svc;
    private readonly IAuditService _audit;
    public DatasetsController(ApplicationDbContext db, DatasetService svc, IAuditService audit) { _db = db; _svc = svc; _audit = audit; }

    private string UserId => User.FindFirstValue(ClaimTypes.NameIdentifier)!;

    public class UploadForm
    {
        public IFormFile File { get; set; } = default!;
        public string? Name { get; set; }
    }

    [HttpPost("upload")]
    [Authorize(Roles = Roles.AnalystOrAdmin)]
    [RequestSizeLimit(250_000_000)]
    [RequestFormLimits(MultipartBodyLengthLimit = 250_000_000)]
    public async Task<IActionResult> Upload([FromForm] UploadForm form, CancellationToken ct)
    {
        if (form.File == null) return BadRequest(new { error = "Attach a CSV as form field 'file'." });
        try
        {
            var ds = await _svc.UploadAsync(form.File, form.Name, UserId, ct);
            await _audit.LogAsync("DatasetUpload", "Dataset", ds.Id.ToString(), $"{ds.OriginalFileName} ({ds.RowCount} rows, {ds.Status})");
            return CreatedAtAction(nameof(Get), new { id = ds.Id }, ToDto(ds));
        }
        catch (ArgumentException ex) { return BadRequest(new { error = ex.Message }); }
    }

    [HttpGet("datasets")]
    public async Task<IActionResult> List([FromQuery] int page = 1, [FromQuery] int pageSize = 20)
    {
        pageSize = Math.Clamp(pageSize, 1, 100); page = Math.Max(page, 1);
        var q = _db.Datasets.AsNoTracking().OrderByDescending(d => d.UploadedAt);
        var total = await q.CountAsync();
        var items = await q.Skip((page - 1) * pageSize).Take(pageSize).ToListAsync();
        return Ok(new { total, page, pageSize, items = items.Select(ToDto) });
    }

    [HttpGet("datasets/{id:int}")]
    public async Task<IActionResult> Get(int id)
    {
        var ds = await _db.Datasets.AsNoTracking().FirstOrDefaultAsync(d => d.Id == id);
        return ds == null ? NotFound() : Ok(ToDto(ds));
    }

    [HttpGet("datasets/{id:int}/preview")]
    public async Task<IActionResult> Preview(int id, [FromQuery] int rows = 20)
    {
        var ds = await _db.Datasets.AsNoTracking().FirstOrDefaultAsync(d => d.Id == id);
        if (ds == null) return NotFound();
        if (!System.IO.File.Exists(ds.StoragePath)) return NotFound(new { error = "File no longer on server." });
        var (cols, data) = DatasetService.Preview(ds.StoragePath, Math.Clamp(rows, 1, 200));
        return Ok(new { columns = cols, rows = data });
    }

    [HttpGet("datasets/{id:int}/stats")]
    public async Task<IActionResult> Stats(int id)
    {
        var ds = await _db.Datasets.AsNoTracking().FirstOrDefaultAsync(d => d.Id == id);
        if (ds == null) return NotFound();
        return Ok(new
        {
            ds.Id, ds.Name, ds.Status, ds.ValidationMessage, ds.RowCount, ds.ColumnCount, ds.HasLabelColumn,
            stats = ds.StatsJson == null ? null : JsonSerializer.Deserialize<JsonElement>(ds.StatsJson)
        });
    }

    [HttpDelete("datasets/{id:int}")]
    [Authorize(Roles = Roles.Admin)]
    public async Task<IActionResult> Delete(int id)
    {
        var ds = await _db.Datasets.FirstOrDefaultAsync(d => d.Id == id);
        if (ds == null) return NotFound();
        var path = ds.StoragePath;
        _db.Datasets.Remove(ds);
        await _db.SaveChangesAsync();
        try { if (System.IO.File.Exists(path)) System.IO.File.Delete(path); } catch { /* best effort */ }
        await _audit.LogAsync("DatasetDelete", "Dataset", id.ToString(), ds.Name);
        return NoContent();
    }

    private static object ToDto(Dataset d) => new
    {
        d.Id, d.Name, d.OriginalFileName, d.SizeBytes, d.RowCount, d.ColumnCount, d.HasLabelColumn,
        d.Status, d.ValidationMessage, d.UploadedAt, d.UploadedByUserId
    };
}
