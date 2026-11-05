using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using ZeroDay.Web.Services;

namespace ZeroDay.Web.Controllers;

public class HomeController : AppController
{
    public HomeController(ApiClient api) : base(api) { }

    public async Task<IActionResult> Index(int days = 30)
    {
        var r = await Api.GetAsync($"/dashboard/summary?days={days}");
        if (await SessionExpired(r) is { } redirect) return redirect;
        if (!r.Ok) ViewData["Error"] = r.Error;
        ViewData["Days"] = days;
        return View(r.Json);
    }

    [AllowAnonymous]
    public IActionResult Error() => View();
}

public class DatasetsController : AppController
{
    public DatasetsController(ApiClient api) : base(api) { }

    public async Task<IActionResult> Index(int page = 1)
    {
        var r = await Api.GetAsync($"/datasets?page={page}&pageSize=20");
        if (await SessionExpired(r) is { } redirect) return redirect;
        if (!r.Ok) ViewData["Error"] = r.Error;
        ViewData["Page"] = page;
        return View(r.Json);
    }

    [HttpPost, ValidateAntiForgeryToken, Authorize(Roles = "Admin,Analyst")]
    public async Task<IActionResult> Upload(IFormFile file, string? name)
    {
        if (file == null || file.Length == 0) { TempData["Error"] = "Choose a CSV file first."; return RedirectToAction(nameof(Index)); }
        using var form = new MultipartFormDataContent();
        await using var stream = file.OpenReadStream();
        form.Add(new StreamContent(stream), "file", file.FileName);
        if (!string.IsNullOrWhiteSpace(name)) form.Add(new StringContent(name), "name");
        var r = await Api.PostFormAsync("/upload", form);
        if (await SessionExpired(r) is { } redirect) return redirect;
        Flash(r, $"Uploaded '{file.FileName}' ({r.Json.S("rowCount")} rows, {r.Json.S("status")}).");
        return r.Ok ? RedirectToAction(nameof(Details), new { id = r.Json.L("id") }) : RedirectToAction(nameof(Index));
    }

    public async Task<IActionResult> Details(int id)
    {
        var info = await Api.GetAsync($"/datasets/{id}");
        if (await SessionExpired(info) is { } redirect) return redirect;
        if (!info.Ok) { TempData["Error"] = info.Error; return RedirectToAction(nameof(Index)); }
        var preview = await Api.GetAsync($"/datasets/{id}/preview?rows=15");
        var stats = await Api.GetAsync($"/datasets/{id}/stats");
        ViewData["Preview"] = preview.Json;
        ViewData["Stats"] = stats.Json;
        return View(info.Json);
    }

    [HttpPost, ValidateAntiForgeryToken, Authorize(Roles = "Admin")]
    public async Task<IActionResult> Delete(int id)
    {
        var r = await Api.DeleteAsync($"/datasets/{id}");
        if (await SessionExpired(r) is { } redirect) return redirect;
        Flash(r, "Dataset deleted.");
        return RedirectToAction(nameof(Index));
    }
}

[Authorize]
public class DetectionController : AppController
{
    public DetectionController(ApiClient api) : base(api) { }

    public async Task<IActionResult> Index()
    {
        var r = await Api.GetAsync("/datasets?page=1&pageSize=100");
        if (await SessionExpired(r) is { } redirect) return redirect;
        if (!r.Ok) ViewData["Error"] = r.Error;
        return View(r.Json);
    }

    [HttpPost, ValidateAntiForgeryToken, Authorize(Roles = "Admin,Analyst")]
    public async Task<IActionResult> Run(IFormFile? file, int? datasetId)
    {
        using var form = new MultipartFormDataContent();
        Stream? stream = null;
        if (file != null && file.Length > 0)
        {
            stream = file.OpenReadStream();
            form.Add(new StreamContent(stream), "file", file.FileName);
        }
        else if (datasetId.HasValue) form.Add(new StringContent(datasetId.Value.ToString()), "datasetId");
        else { TempData["Error"] = "Upload a CSV or choose an existing dataset."; return RedirectToAction(nameof(Index)); }

        ApiResult r;
        try { r = await Api.PostFormAsync("/predict", form); }
        finally { if (stream != null) await stream.DisposeAsync(); }

        if (await SessionExpired(r) is { } redirect) return redirect;
        if (!r.Ok) { TempData["Error"] = r.Error; return RedirectToAction(nameof(Index)); }
        return View("Result", r.Json);
    }
}

public class ThreatsController : AppController
{
    public ThreatsController(ApiClient api) : base(api) { }

    public async Task<IActionResult> Index(string? severity, string? type, int? predictionId, int page = 1)
    {
        var qs = $"page={page}&pageSize=50";
        if (!string.IsNullOrEmpty(severity)) qs += "&severity=" + Uri.EscapeDataString(severity);
        if (!string.IsNullOrEmpty(type)) qs += "&type=" + Uri.EscapeDataString(type);
        if (predictionId.HasValue) qs += "&predictionId=" + predictionId;
        var r = await Api.GetAsync("/threats?" + qs);
        if (await SessionExpired(r) is { } redirect) return redirect;
        if (!r.Ok) ViewData["Error"] = r.Error;
        ViewData["Severity"] = severity; ViewData["Type"] = type; ViewData["PredictionId"] = predictionId; ViewData["Page"] = page;
        return View(r.Json);
    }
}

public class AlertsController : AppController
{
    public AlertsController(ApiClient api) : base(api) { }

    public async Task<IActionResult> Index(string? status, string? severity, int page = 1)
    {
        var qs = $"page={page}&pageSize=50";
        if (!string.IsNullOrEmpty(status)) qs += "&status=" + status;
        if (!string.IsNullOrEmpty(severity)) qs += "&severity=" + severity;
        var r = await Api.GetAsync("/alerts?" + qs);
        if (await SessionExpired(r) is { } redirect) return redirect;
        if (!r.Ok) ViewData["Error"] = r.Error;
        ViewData["Status"] = status; ViewData["Severity"] = severity; ViewData["Page"] = page;
        return View(r.Json);
    }

    [HttpPost, ValidateAntiForgeryToken, Authorize(Roles = "Admin,Analyst")]
    public async Task<IActionResult> SetStatus(long id, string status, string? status0)
    {
        var r = await Api.PutJsonAsync($"/alerts/{id}/status", new { status });
        if (await SessionExpired(r) is { } redirect) return redirect;
        Flash(r, $"Alert #{id} marked {status}.");
        return RedirectToAction(nameof(Index), new { status = status0 });
    }
}

public class ReportsController : AppController
{
    public ReportsController(ApiClient api) : base(api) { }

    public async Task<IActionResult> Index()
    {
        var reports = await Api.GetAsync("/reports?page=1&pageSize=50");
        if (await SessionExpired(reports) is { } redirect) return redirect;
        var preds = await Api.GetAsync("/predictions?page=1&pageSize=50");
        if (!reports.Ok) ViewData["Error"] = reports.Error;
        ViewData["Predictions"] = preds.Json;
        return View(reports.Json);
    }

    [HttpPost, ValidateAntiForgeryToken, Authorize(Roles = "Admin,Analyst")]
    public async Task<IActionResult> Create(int predictionId, string type)
    {
        var r = await Api.PostJsonAsync("/reports", new { predictionId, type });
        if (await SessionExpired(r) is { } redirect) return redirect;
        Flash(r, "Report generated.");
        return RedirectToAction(nameof(Index));
    }

    public async Task<IActionResult> Pdf(int id)
    {
        var r = await Api.GetAsync($"/reports/{id}/pdf");
        if (await SessionExpired(r) is { } redirect) return redirect;
        if (!r.Ok || r.Bytes == null) { TempData["Error"] = r.Error ?? "Could not export PDF."; return RedirectToAction(nameof(Index)); }
        return File(r.Bytes, "application/pdf", $"report-{id}.pdf");
    }
}

[Authorize(Roles = "Admin")]
public class AdminController : AppController
{
    public AdminController(ApiClient api) : base(api) { }

    public async Task<IActionResult> Users()
    {
        var r = await Api.GetAsync("/admin/users");
        if (await SessionExpired(r) is { } redirect) return redirect;
        if (!r.Ok) ViewData["Error"] = r.Error;
        return View(r.Json);
    }

    [HttpPost, ValidateAntiForgeryToken]
    public async Task<IActionResult> SetRole(string id, string role)
    {
        var r = await Api.PutJsonAsync($"/admin/users/{id}/role", new { role });
        if (await SessionExpired(r) is { } redirect) return redirect;
        Flash(r, "Role updated.");
        return RedirectToAction(nameof(Users));
    }

    [HttpPost, ValidateAntiForgeryToken]
    public async Task<IActionResult> SetActive(string id, bool value)
    {
        var r = await Api.PutJsonAsync($"/admin/users/{id}/active?value={value.ToString().ToLower()}", new { });
        if (await SessionExpired(r) is { } redirect) return redirect;
        Flash(r, value ? "User activated." : "User deactivated.");
        return RedirectToAction(nameof(Users));
    }

    public async Task<IActionResult> Audit(string? auditAction, string? email, int page = 1)
    {
        var qs = $"page={page}&pageSize=50";
        if (!string.IsNullOrEmpty(auditAction)) qs += "&action=" + Uri.EscapeDataString(auditAction);
        if (!string.IsNullOrEmpty(email)) qs += "&email=" + Uri.EscapeDataString(email);
        var r = await Api.GetAsync("/audit-logs?" + qs);
        if (await SessionExpired(r) is { } redirect) return redirect;
        if (!r.Ok) ViewData["Error"] = r.Error;
        ViewData["Action"] = auditAction; ViewData["Email"] = email; ViewData["Page"] = page;
        return View(r.Json);
    }
}
