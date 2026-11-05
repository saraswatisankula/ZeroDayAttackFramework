using System.Globalization;
using System.Text;
using System.Text.Json;
using ZeroDay.Api.Data;
using ZeroDay.Api.Models;

namespace ZeroDay.Api.Services;

public static class CsvLite
{
    /// <summary>Splits one CSV line, honouring double quotes.</summary>
    public static List<string> SplitLine(string line)
    {
        var res = new List<string>();
        var sb = new StringBuilder();
        bool q = false;
        for (int i = 0; i < line.Length; i++)
        {
            char c = line[i];
            if (c == '"') { if (q && i + 1 < line.Length && line[i + 1] == '"') { sb.Append('"'); i++; } else q = !q; }
            else if (c == ',' && !q) { res.Add(sb.ToString()); sb.Clear(); }
            else sb.Append(c);
        }
        res.Add(sb.ToString());
        return res;
    }

    public static double? ParseDouble(string s)
    {
        if (double.TryParse(s, NumberStyles.Float, CultureInfo.InvariantCulture, out var d) && double.IsFinite(d)) return d;
        return null;
    }
}

public class DatasetService
{
    private const int SampleRows = 20000;
    private static readonly string[] KeyCols =
        { "Destination Port", "Flow Duration", "Total Fwd Packets", "Total Backward Packets", "Flow Bytes/s", "Flow Packets/s" };

    private readonly ApplicationDbContext _db;
    private readonly IConfiguration _cfg;
    public DatasetService(ApplicationDbContext db, IConfiguration cfg) { _db = db; _cfg = cfg; }

    public async Task<Dataset> UploadAsync(IFormFile file, string? name, string userId, CancellationToken ct)
    {
        long maxBytes = _cfg.GetValue<long?>("Upload:MaxBytes") ?? 209_715_200;
        if (file.Length == 0) throw new ArgumentException("The uploaded file is empty.");
        if (file.Length > maxBytes) throw new ArgumentException($"File exceeds the {maxBytes / 1_048_576} MB upload limit.");
        if (!Path.GetExtension(file.FileName).Equals(".csv", StringComparison.OrdinalIgnoreCase))
            throw new ArgumentException("Only .csv files are accepted.");

        var dir = Path.GetFullPath(_cfg["Upload:Path"] ?? "uploads");
        Directory.CreateDirectory(dir);
        var stored = Path.Combine(dir, $"{Guid.NewGuid():N}.csv");
        await using (var fs = File.Create(stored)) await file.CopyToAsync(fs, ct);

        var ds = new Dataset
        {
            Name = string.IsNullOrWhiteSpace(name) ? Path.GetFileNameWithoutExtension(file.FileName) : name.Trim(),
            OriginalFileName = Path.GetFileName(file.FileName),
            StoragePath = stored,
            SizeBytes = file.Length,
            UploadedByUserId = userId,
            UploadedAt = DateTime.UtcNow
        };
        if (ds.Name.Length > 200) ds.Name = ds.Name[..200];

        var flows = new List<NetworkTraffic>();
        try { Analyze(ds, stored, flows); }
        catch (Exception ex) { ds.Status = "Invalid"; ds.ValidationMessage = "Could not parse file: " + ex.Message; flows.Clear(); }

        _db.Datasets.Add(ds);
        await _db.SaveChangesAsync(ct);
        if (flows.Count > 0)
        {
            foreach (var f in flows) f.DatasetId = ds.Id;
            _db.NetworkTraffic.AddRange(flows);
            await _db.SaveChangesAsync(ct);
        }
        return ds;
    }

    private void Analyze(Dataset ds, string path, List<NetworkTraffic> flows)
    {
        int storeRows = _cfg.GetValue<int?>("Upload:StoreFlowRows") ?? 5000;
        using var sr = new StreamReader(path, Encoding.Latin1);
        var headerLine = sr.ReadLine();
        if (string.IsNullOrWhiteSpace(headerLine)) { ds.Status = "Invalid"; ds.ValidationMessage = "File has no header row."; return; }

        var header = CsvLite.SplitLine(headerLine).Select(h => h.Trim()).ToList();
        ds.ColumnCount = header.Count;
        int labelIdx = header.FindIndex(h => h.Equals("Label", StringComparison.OrdinalIgnoreCase));
        ds.HasLabelColumn = labelIdx >= 0;
        var dupHeaders = header.GroupBy(h => h).Where(g => g.Count() > 1).Select(g => g.Key).ToList();
        var keyIdx = KeyCols.ToDictionary(k => k, k => header.FindIndex(h => h.Equals(k, StringComparison.OrdinalIgnoreCase)));

        int rows = 0, sampled = 0, malformed = 0;
        long missing = 0, infinite = 0;
        var numericOk = new bool[header.Count];
        Array.Fill(numericOk, true);
        var seenValue = new bool[header.Count];
        var labels = new Dictionary<string, int>();

        string? line;
        while ((line = sr.ReadLine()) != null)
        {
            if (line.Length == 0) continue;
            rows++;
            if (sampled >= SampleRows && flows.Count >= storeRows) continue;   // just count remaining rows
            var cells = CsvLite.SplitLine(line);
            if (sampled < SampleRows)
            {
                sampled++;
                if (cells.Count != header.Count) { malformed++; }
                else
                {
                    for (int i = 0; i < cells.Count; i++)
                    {
                        var c = cells[i].Trim();
                        if (i == labelIdx) { labels[c] = labels.GetValueOrDefault(c) + 1; continue; }
                        if (c.Length == 0 || c.Equals("nan", StringComparison.OrdinalIgnoreCase)) { missing++; continue; }
                        if (c.Contains("inf", StringComparison.OrdinalIgnoreCase)) { infinite++; continue; }
                        seenValue[i] = true;
                        if (sampled <= 200 && numericOk[i] && !double.TryParse(c, NumberStyles.Float, CultureInfo.InvariantCulture, out _))
                            numericOk[i] = false;
                    }
                }
            }
            if (flows.Count < storeRows && cells.Count == header.Count)
            {
                string? Cell(string k) => keyIdx[k] >= 0 ? cells[keyIdx[k]].Trim() : null;
                var port = Cell("Destination Port");
                flows.Add(new NetworkTraffic
                {
                    FlowIndex = rows - 1,
                    DestinationPort = port != null && double.TryParse(port, NumberStyles.Float, CultureInfo.InvariantCulture, out var p) && double.IsFinite(p) ? (int)p : null,
                    FlowDuration = Cell("Flow Duration") is { } a ? CsvLite.ParseDouble(a) : null,
                    TotalFwdPackets = Cell("Total Fwd Packets") is { } b ? CsvLite.ParseDouble(b) : null,
                    TotalBwdPackets = Cell("Total Backward Packets") is { } c2 ? CsvLite.ParseDouble(c2) : null,
                    FlowBytesPerSec = Cell("Flow Bytes/s") is { } d ? CsvLite.ParseDouble(d) : null,
                    FlowPacketsPerSec = Cell("Flow Packets/s") is { } e ? CsvLite.ParseDouble(e) : null,
                    Label = labelIdx >= 0 ? cells[labelIdx].Trim() : null
                });
            }
        }

        ds.RowCount = rows;
        int numericCols = Enumerable.Range(0, header.Count).Count(i => i != labelIdx && numericOk[i] && seenValue[i]);
        var problems = new List<string>();
        if (rows == 0) problems.Add("File contains no data rows.");
        if (header.Count < 5) problems.Add("Fewer than 5 columns.");
        if (numericCols < 5) problems.Add($"Only {numericCols} numeric feature columns detected (need at least 5).");
        if (sampled > 0 && malformed * 20 > sampled) problems.Add($"{malformed} of {sampled} sampled rows have the wrong number of columns.");

        ds.Status = problems.Count == 0 ? "Validated" : "Invalid";
        var notes = new List<string>(problems);
        if (!ds.HasLabelColumn) notes.Add("No 'Label' column; fine for prediction but accuracy cannot be computed.");
        if (dupHeaders.Count > 0) notes.Add($"Duplicate column names: {string.Join(", ", dupHeaders.Take(5))}.");
        ds.ValidationMessage = notes.Count == 0 ? "OK" : string.Join(" ", notes);
        if (ds.ValidationMessage.Length > 1000) ds.ValidationMessage = ds.ValidationMessage[..1000];

        ds.StatsJson = JsonSerializer.Serialize(new
        {
            rows,
            columns = header.Count,
            numericColumns = numericCols,
            sampledRows = sampled,
            malformedRowsInSample = malformed,
            missingCellsInSample = missing,
            infiniteCellsInSample = infinite,
            storedFlowRows = flows.Count,
            labelDistribution = labels.OrderByDescending(kv => kv.Value).Take(30).ToDictionary(kv => kv.Key, kv => kv.Value)
        });
        if (ds.Status == "Invalid") flows.Clear();
    }

    public static (List<string> Columns, List<string[]> Rows) Preview(string path, int rows)
    {
        using var sr = new StreamReader(path, Encoding.Latin1);
        var header = CsvLite.SplitLine(sr.ReadLine() ?? "").Select(h => h.Trim()).ToList();
        var data = new List<string[]>();
        string? line;
        while (data.Count < rows && (line = sr.ReadLine()) != null)
            if (line.Length > 0) data.Add(CsvLite.SplitLine(line).ToArray());
        return (header, data);
    }
}
