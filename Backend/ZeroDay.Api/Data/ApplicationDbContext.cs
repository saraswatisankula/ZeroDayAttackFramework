using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using ZeroDay.Api.Models;

namespace ZeroDay.Api.Data;

public class ApplicationDbContext : IdentityDbContext<ApplicationUser, ApplicationRole, string>
{
    public ApplicationDbContext(DbContextOptions<ApplicationDbContext> options) : base(options) { }

    public DbSet<Dataset> Datasets => Set<Dataset>();
    public DbSet<NetworkTraffic> NetworkTraffic => Set<NetworkTraffic>();
    public DbSet<Prediction> Predictions => Set<Prediction>();
    public DbSet<RiskScore> RiskScores => Set<RiskScore>();
    public DbSet<Threat> Threats => Set<Threat>();
    public DbSet<Alert> Alerts => Set<Alert>();
    public DbSet<Report> Reports => Set<Report>();
    public DbSet<AuditLog> AuditLogs => Set<AuditLog>();

    protected override void OnModelCreating(ModelBuilder b)
    {
        base.OnModelCreating(b);

        // Identity tables renamed to match the requested schema
        b.Entity<ApplicationUser>().ToTable("Users");
        b.Entity<ApplicationRole>().ToTable("Roles");
        b.Entity<IdentityUserRole<string>>().ToTable("UserRoles");
        b.Entity<IdentityUserClaim<string>>().ToTable("UserClaims");
        b.Entity<IdentityRoleClaim<string>>().ToTable("RoleClaims");
        b.Entity<IdentityUserLogin<string>>().ToTable("UserLogins");
        b.Entity<IdentityUserToken<string>>().ToTable("UserTokens");

        b.Entity<Dataset>(e =>
        {
            e.ToTable("Datasets");
            e.Property(x => x.Name).HasMaxLength(200).IsRequired();
            e.Property(x => x.OriginalFileName).HasMaxLength(260).IsRequired();
            e.Property(x => x.StoragePath).HasMaxLength(500).IsRequired();
            e.Property(x => x.Status).HasMaxLength(20).IsRequired();
            e.Property(x => x.ValidationMessage).HasMaxLength(1000);
            e.HasOne(x => x.UploadedBy).WithMany().HasForeignKey(x => x.UploadedByUserId).OnDelete(DeleteBehavior.NoAction);
            e.HasIndex(x => x.UploadedByUserId);
        });

        b.Entity<NetworkTraffic>(e =>
        {
            e.ToTable("NetworkTraffic");
            e.Property(x => x.Label).HasMaxLength(100);
            e.HasOne(x => x.Dataset).WithMany(d => d.Flows).HasForeignKey(x => x.DatasetId).OnDelete(DeleteBehavior.Cascade);
            e.HasIndex(x => new { x.DatasetId, x.FlowIndex }).IsUnique();
        });

        b.Entity<Prediction>(e =>
        {
            e.ToTable("Predictions");
            e.Property(x => x.RiskHistogramJson).IsRequired();
            e.Property(x => x.ThreatTypeCountsJson).IsRequired();
            e.HasOne(x => x.Dataset).WithMany(d => d.Predictions).HasForeignKey(x => x.DatasetId).OnDelete(DeleteBehavior.Cascade);
            e.HasOne(x => x.User).WithMany().HasForeignKey(x => x.UserId).OnDelete(DeleteBehavior.NoAction);
            e.HasIndex(x => x.DatasetId);
            e.HasIndex(x => x.UserId);
            e.HasIndex(x => x.CreatedAt);
        });

        b.Entity<RiskScore>(e =>
        {
            e.ToTable("RiskScores", t => t.HasCheckConstraint("CK_RiskScores_Score", "[Score] BETWEEN 0 AND 100"));
            e.Property(x => x.Severity).HasMaxLength(20).IsRequired();
            e.HasOne(x => x.Prediction).WithMany(p => p.RiskScores).HasForeignKey(x => x.PredictionId).OnDelete(DeleteBehavior.Cascade);
            e.HasIndex(x => x.PredictionId);
        });

        b.Entity<Threat>(e =>
        {
            e.ToTable("Threats", t => t.HasCheckConstraint("CK_Threats_Risk", "[RiskScore] BETWEEN 0 AND 100"));
            e.Property(x => x.ThreatType).HasMaxLength(50).IsRequired();
            e.Property(x => x.Severity).HasMaxLength(20).IsRequired();
            e.Property(x => x.Description).HasMaxLength(500).IsRequired();
            e.HasOne(x => x.Prediction).WithMany(p => p.Threats).HasForeignKey(x => x.PredictionId).OnDelete(DeleteBehavior.Cascade);
            e.HasIndex(x => x.PredictionId);
            e.HasIndex(x => new { x.ThreatType, x.Severity });
        });

        b.Entity<Alert>(e =>
        {
            e.ToTable("Alerts", t => t.HasCheckConstraint("CK_Alerts_Status", "[Status] IN ('Open','Acknowledged','Resolved')"));
            e.Property(x => x.Title).HasMaxLength(200).IsRequired();
            e.Property(x => x.Severity).HasMaxLength(20).IsRequired();
            e.Property(x => x.Status).HasMaxLength(20).IsRequired();
            e.HasOne(x => x.Threat).WithMany(t => t.Alerts).HasForeignKey(x => x.ThreatId).OnDelete(DeleteBehavior.Cascade);
            e.HasOne(x => x.AcknowledgedBy).WithMany().HasForeignKey(x => x.AcknowledgedByUserId).OnDelete(DeleteBehavior.NoAction);
            e.HasIndex(x => new { x.Status, x.CreatedAt });
            e.HasIndex(x => x.ThreatId);
        });

        b.Entity<Report>(e =>
        {
            e.ToTable("Reports", t => t.HasCheckConstraint("CK_Reports_Type", "[Type] IN ('Threat','Risk')"));
            e.Property(x => x.Type).HasMaxLength(30).IsRequired();
            e.Property(x => x.Title).HasMaxLength(200).IsRequired();
            e.HasOne(x => x.Prediction).WithMany().HasForeignKey(x => x.PredictionId).OnDelete(DeleteBehavior.SetNull);
            e.HasOne(x => x.GeneratedBy).WithMany().HasForeignKey(x => x.GeneratedByUserId).OnDelete(DeleteBehavior.NoAction);
            e.HasIndex(x => x.GeneratedByUserId);
        });

        b.Entity<AuditLog>(e =>
        {
            e.ToTable("AuditLogs");
            e.Property(x => x.Action).HasMaxLength(100).IsRequired();
            e.Property(x => x.UserEmail).HasMaxLength(256);
            e.Property(x => x.EntityType).HasMaxLength(100);
            e.Property(x => x.EntityId).HasMaxLength(100);
            e.Property(x => x.Details).HasMaxLength(1000);
            e.Property(x => x.IpAddress).HasMaxLength(64);
            e.HasOne(x => x.User).WithMany().HasForeignKey(x => x.UserId).OnDelete(DeleteBehavior.SetNull);
            e.HasIndex(x => x.Timestamp);
            e.HasIndex(x => x.Action);
        });
    }
}
