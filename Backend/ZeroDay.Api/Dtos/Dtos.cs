namespace ZeroDay.Api.Dtos;

public record RegisterRequest(string Email, string Password, string FullName);
public record LoginRequest(string Email, string Password);
public record ForgotPasswordRequest(string Email);
public record ResetPasswordRequest(string Email, string Token, string NewPassword);
public record AuthResponse(string Token, DateTime ExpiresAt, string Email, string FullName, string[] Roles);
public record SetRoleRequest(string Role);
public record UpdateAlertStatusRequest(string Status);
public record CreateReportRequest(int PredictionId, string Type);

// ---- shape returned by the Python ML service (FastAPI /predict)
public class MlResult
{
    public int FlowId { get; set; }
    public int RiskScore { get; set; }
    public string ThreatType { get; set; } = "Benign";
    public string Severity { get; set; } = "Low";
    public string Confidence { get; set; } = "0%";
    public double AnomalyScore { get; set; }
    public double SupervisedProbability { get; set; }
}

public class MlSummary
{
    public int TotalFlows { get; set; }
    public int Threats { get; set; }
    public int ZeroDayDetections { get; set; }
    public int HighRiskAlerts { get; set; }
    public Dictionary<string, int> ByThreatType { get; set; } = new();
    public Dictionary<string, int> BySeverity { get; set; } = new();
    public double Threshold { get; set; }
    public double BlendWeight { get; set; }
}

public class MlPredictResponse
{
    public MlSummary Summary { get; set; } = new();
    public List<MlResult> Results { get; set; } = new();
}
