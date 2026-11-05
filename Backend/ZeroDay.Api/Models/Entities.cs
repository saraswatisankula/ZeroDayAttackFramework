using Microsoft.AspNetCore.Identity;

namespace ZeroDay.Api.Models;

public class ApplicationUser : IdentityUser
{
    public string FullName { get; set; } = "";
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
    public bool IsActive { get; set; } = true;
}

public class ApplicationRole : IdentityRole
{
    public ApplicationRole() { }
    public ApplicationRole(string name) : base(name) { }
    public string? Description { get; set; }
}

public static class Roles
{
    public const string Admin = "Admin";
    public const string Analyst = "Analyst";
    public const string Viewer = "Viewer";
    public const string AnalystOrAdmin = Admin + "," + Analyst;
}

public class Dataset
{
    public int Id { get; set; }
    public string Name { get; set; } = "";
    public string OriginalFileName { get; set; } = "";
    public string StoragePath { get; set; } = "";
    public long SizeBytes { get; set; }
    public int RowCount { get; set; }
    public int ColumnCount { get; set; }
    public bool HasLabelColumn { get; set; }
    public string Status { get; set; } = "Validated";   // Validated | Invalid
    public string? ValidationMessage { get; set; }
    public string? StatsJson { get; set; }
    public string UploadedByUserId { get; set; } = "";
    public ApplicationUser? UploadedBy { get; set; }
    public DateTime UploadedAt { get; set; } = DateTime.UtcNow;
    public List<NetworkTraffic> Flows { get; set; } = new();
    public List<Prediction> Predictions { get; set; } = new();
}

public class NetworkTraffic
{
    public long Id { get; set; }
    public int DatasetId { get; set; }
    public Dataset? Dataset { get; set; }
    public int FlowIndex { get; set; }
    public int? DestinationPort { get; set; }
    public double? FlowDuration { get; set; }
    public double? TotalFwdPackets { get; set; }
    public double? TotalBwdPackets { get; set; }
    public double? FlowBytesPerSec { get; set; }
    public double? FlowPacketsPerSec { get; set; }
    public string? Label { get; set; }
}

public class Prediction
{
    public int Id { get; set; }
    public int DatasetId { get; set; }
    public Dataset? Dataset { get; set; }
    public string UserId { get; set; } = "";
    public ApplicationUser? User { get; set; }
    public int TotalFlows { get; set; }
    public int ThreatCount { get; set; }
    public int ZeroDayCount { get; set; }
    public int HighRiskCount { get; set; }
    public double MeanRisk { get; set; }
    public string RiskHistogramJson { get; set; } = "[]";
    public string ThreatTypeCountsJson { get; set; } = "{}";
    public double Threshold { get; set; }
    public double BlendWeight { get; set; }
    public int StoredThreats { get; set; }
    public bool Truncated { get; set; }
    public int DurationMs { get; set; }
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
    public List<RiskScore> RiskScores { get; set; } = new();
    public List<Threat> Threats { get; set; } = new();
}

public class RiskScore
{
    public long Id { get; set; }
    public int PredictionId { get; set; }
    public Prediction? Prediction { get; set; }
    public int FlowIndex { get; set; }
    public int Score { get; set; }
    public string Severity { get; set; } = "Low";
    public double AnomalyScore { get; set; }
    public double SupervisedProbability { get; set; }
    public int Confidence { get; set; }
}

public class Threat
{
    public long Id { get; set; }
    public int PredictionId { get; set; }
    public Prediction? Prediction { get; set; }
    public int FlowIndex { get; set; }
    public string ThreatType { get; set; } = "";
    public string Severity { get; set; } = "";
    public int RiskScore { get; set; }
    public double AnomalyScore { get; set; }
    public double SupervisedProbability { get; set; }
    public string Description { get; set; } = "";
    public DateTime DetectedAt { get; set; } = DateTime.UtcNow;
    public List<Alert> Alerts { get; set; } = new();
}

public class Alert
{
    public long Id { get; set; }
    public long ThreatId { get; set; }
    public Threat? Threat { get; set; }
    public string Title { get; set; } = "";
    public string Severity { get; set; } = "";
    public string Status { get; set; } = "Open";   // Open | Acknowledged | Resolved
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
    public DateTime? AcknowledgedAt { get; set; }
    public string? AcknowledgedByUserId { get; set; }
    public ApplicationUser? AcknowledgedBy { get; set; }
}

public class Report
{
    public int Id { get; set; }
    public string Type { get; set; } = "Threat";   // Threat | Risk
    public string Title { get; set; } = "";
    public int? PredictionId { get; set; }
    public Prediction? Prediction { get; set; }
    public string GeneratedByUserId { get; set; } = "";
    public ApplicationUser? GeneratedBy { get; set; }
    public string ContentJson { get; set; } = "{}";
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
}

public class AuditLog
{
    public long Id { get; set; }
    public string? UserId { get; set; }
    public ApplicationUser? User { get; set; }
    public string? UserEmail { get; set; }
    public string Action { get; set; } = "";
    public string? EntityType { get; set; }
    public string? EntityId { get; set; }
    public string? Details { get; set; }
    public string? IpAddress { get; set; }
    public DateTime Timestamp { get; set; } = DateTime.UtcNow;
}
