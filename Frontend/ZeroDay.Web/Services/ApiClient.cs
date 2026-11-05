using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;

namespace ZeroDay.Web.Services;

public class ApiResult
{
    public bool Ok { get; init; }
    public int Status { get; init; }
    public JsonElement Json { get; init; }
    public byte[]? Bytes { get; init; }
    public string? ContentType { get; init; }
    public string? Error { get; init; }
}

/// <summary>Thin wrapper over the REST API; forwards the signed-in user's JWT (kept in the auth cookie).</summary>
public class ApiClient
{
    private readonly HttpClient _http;
    private readonly IHttpContextAccessor _ctx;
    public ApiClient(HttpClient http, IHttpContextAccessor ctx) { _http = http; _ctx = ctx; }

    public Task<ApiResult> GetAsync(string path) => SendAsync(HttpMethod.Get, path, null);
    public Task<ApiResult> DeleteAsync(string path) => SendAsync(HttpMethod.Delete, path, null);
    public Task<ApiResult> PostJsonAsync(string path, object body) => SendAsync(HttpMethod.Post, path, Json(body));
    public Task<ApiResult> PutJsonAsync(string path, object body) => SendAsync(HttpMethod.Put, path, Json(body));
    public Task<ApiResult> PostFormAsync(string path, MultipartFormDataContent form) => SendAsync(HttpMethod.Post, path, form);

    private static StringContent Json(object o) => new(JsonSerializer.Serialize(o), Encoding.UTF8, "application/json");

    private async Task<ApiResult> SendAsync(HttpMethod method, string path, HttpContent? content)
    {
        using var req = new HttpRequestMessage(method, path) { Content = content };
        var token = _ctx.HttpContext?.User.FindFirst("access_token")?.Value;
        if (!string.IsNullOrEmpty(token)) req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
        try
        {
            using var resp = await _http.SendAsync(req);
            var ctype = resp.Content.Headers.ContentType?.MediaType;
            if (ctype == "application/pdf")
                return new ApiResult { Ok = resp.IsSuccessStatusCode, Status = (int)resp.StatusCode, Bytes = await resp.Content.ReadAsByteArrayAsync(), ContentType = ctype };

            var text = await resp.Content.ReadAsStringAsync();
            JsonElement json = default;
            if (!string.IsNullOrWhiteSpace(text) && (ctype?.Contains("json") ?? false))
            {
                try { json = JsonDocument.Parse(text).RootElement.Clone(); } catch { /* non-JSON body */ }
            }
            string? err = null;
            if (!resp.IsSuccessStatusCode)
            {
                err = json.ValueKind == JsonValueKind.Object && json.TryGetProperty("error", out var e) ? e.ToString()
                      : $"Request failed ({(int)resp.StatusCode}).";
                if (json.ValueKind == JsonValueKind.Object && json.TryGetProperty("details", out var d) && d.ValueKind == JsonValueKind.Array)
                    err += " " + string.Join(" ", d.EnumerateArray().Select(x => x.ToString()));
            }
            return new ApiResult { Ok = resp.IsSuccessStatusCode, Status = (int)resp.StatusCode, Json = json, Error = err };
        }
        catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException)
        {
            return new ApiResult { Ok = false, Status = 503, Error = "The API is unreachable or timed out. " + ex.Message };
        }
    }
}

public static class Js
{
    public static JsonElement P(this JsonElement e, string name) =>
        e.ValueKind == JsonValueKind.Object && e.TryGetProperty(name, out var v) ? v : default;

    public static string S(this JsonElement e, string name, string dflt = "") =>
        e.ValueKind == JsonValueKind.Object && e.TryGetProperty(name, out var v) && v.ValueKind != JsonValueKind.Null ? v.ToString() : dflt;

    public static long L(this JsonElement e, string name) =>
        e.ValueKind == JsonValueKind.Object && e.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.Number ? v.GetInt64() : 0;

    public static IEnumerable<JsonElement> A(this JsonElement e, string name)
    {
        var v = e.P(name);
        return v.ValueKind == JsonValueKind.Array ? v.EnumerateArray().ToList() : new List<JsonElement>();
    }

    public static string Raw(this JsonElement e) =>
        e.ValueKind == JsonValueKind.Undefined ? "null" : e.GetRawText().Replace("<", "\\u003c");   // safe inside <script>

    public static string Badge(string? severity) => severity switch
    {
        "Critical" => "bg-danger",
        "High" => "bg-warning text-dark",
        "Medium" => "bg-info text-dark",
        "Open" => "bg-danger",
        "Acknowledged" => "bg-warning text-dark",
        "Resolved" => "bg-success",
        "Validated" => "bg-success",
        "Invalid" => "bg-danger",
        _ => "bg-secondary"
    };
}
