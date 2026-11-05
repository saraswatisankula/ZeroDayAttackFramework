using System.Security.Claims;
using ZeroDay.Api.Data;
using ZeroDay.Api.Models;

namespace ZeroDay.Api.Services;

public interface IAuditService
{
    Task LogAsync(string action, string? entityType = null, string? entityId = null, string? details = null,
                  string? userId = null, string? email = null);
}

public class AuditService : IAuditService
{
    private readonly ApplicationDbContext _db;
    private readonly IHttpContextAccessor _http;
    public AuditService(ApplicationDbContext db, IHttpContextAccessor http) { _db = db; _http = http; }

    public async Task LogAsync(string action, string? entityType = null, string? entityId = null, string? details = null,
                               string? userId = null, string? email = null)
    {
        var ctx = _http.HttpContext;
        userId ??= ctx?.User.FindFirstValue(ClaimTypes.NameIdentifier);
        email ??= ctx?.User.FindFirstValue(ClaimTypes.Email) ?? ctx?.User.FindFirstValue("email");
        _db.AuditLogs.Add(new AuditLog
        {
            UserId = userId,
            UserEmail = email,
            Action = action,
            EntityType = entityType,
            EntityId = entityId,
            Details = details is { Length: > 1000 } ? details[..1000] : details,
            IpAddress = ctx?.Connection.RemoteIpAddress?.ToString(),
            Timestamp = DateTime.UtcNow
        });
        await _db.SaveChangesAsync();
    }
}
