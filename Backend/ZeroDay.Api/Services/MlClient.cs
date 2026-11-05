using System.Net.Http.Headers;
using System.Text.Json;
using ZeroDay.Api.Dtos;

namespace ZeroDay.Api.Services;

public class MlClient
{
    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web);
    private readonly HttpClient _http;
    private readonly string _apiKey;
    private readonly ILogger<MlClient> _log;

    public MlClient(HttpClient http, IConfiguration cfg, ILogger<MlClient> log)
    {
        _http = http;
        _log = log;
        _apiKey = cfg["Ml:ApiKey"] ?? "";
    }

    public async Task<MlPredictResponse> PredictAsync(string path, string fileName, int maxRows, CancellationToken ct)
    {
        using var form = new MultipartFormDataContent();
        await using var fs = File.OpenRead(path);
        var sc = new StreamContent(fs);
        sc.Headers.ContentType = new MediaTypeHeaderValue("text/csv");
        form.Add(sc, "file", fileName);

        using var req = new HttpRequestMessage(HttpMethod.Post, $"/predict?max_rows={maxRows}") { Content = form };
        if (_apiKey.Length > 0) req.Headers.Add("x-api-key", _apiKey);

        using var resp = await _http.SendAsync(req, ct);
        var body = await resp.Content.ReadAsStringAsync(ct);
        if (!resp.IsSuccessStatusCode)
        {
            _log.LogWarning("ML service returned {Status}: {Body}", (int)resp.StatusCode, body);
            throw new MlServiceException($"ML service error {(int)resp.StatusCode}: {Truncate(body, 300)}");
        }
        return JsonSerializer.Deserialize<MlPredictResponse>(body, Json)
               ?? throw new MlServiceException("ML service returned an empty response.");
    }

    public async Task<JsonElement?> HealthAsync(CancellationToken ct = default)
    {
        try
        {
            using var resp = await _http.GetAsync("/health", ct);
            if (!resp.IsSuccessStatusCode) return null;
            return JsonSerializer.Deserialize<JsonElement>(await resp.Content.ReadAsStringAsync(ct), Json);
        }
        catch (Exception ex)
        {
            _log.LogWarning(ex, "ML health check failed");
            return null;
        }
    }

    private static string Truncate(string s, int n) => s.Length <= n ? s : s[..n];
}

public class MlServiceException : Exception
{
    public MlServiceException(string message) : base(message) { }
}
