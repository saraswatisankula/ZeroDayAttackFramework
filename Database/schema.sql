/* ============================================================================
   Zero-Day Attack Framework - SQL Server schema (SQL Server 2019+ / Azure SQL)
   Matches the EF Core model in Backend/ZeroDay.Api. Use EITHER this script OR the
   app's automatic creation (Database__AutoCreate=true) on an empty database.
   On Azure SQL create the database in the portal and skip the first block.
   ============================================================================ */
IF DB_ID(N'ZeroDayDb') IS NULL CREATE DATABASE ZeroDayDb;
GO
USE ZeroDayDb;
GO

/* ---------- ASP.NET Identity tables (renamed: Users, Roles, ...) ---------- */
CREATE TABLE dbo.Roles (
    Id               NVARCHAR(450) NOT NULL CONSTRAINT PK_Roles PRIMARY KEY,
    Name             NVARCHAR(256) NULL,
    NormalizedName   NVARCHAR(256) NULL,
    ConcurrencyStamp NVARCHAR(MAX) NULL,
    Description      NVARCHAR(MAX) NULL
);
CREATE UNIQUE INDEX RoleNameIndex ON dbo.Roles(NormalizedName) WHERE NormalizedName IS NOT NULL;

CREATE TABLE dbo.Users (
    Id                   NVARCHAR(450) NOT NULL CONSTRAINT PK_Users PRIMARY KEY,
    FullName             NVARCHAR(MAX) NOT NULL,
    CreatedAt            DATETIME2 NOT NULL,
    IsActive             BIT NOT NULL,
    UserName             NVARCHAR(256) NULL,
    NormalizedUserName   NVARCHAR(256) NULL,
    Email                NVARCHAR(256) NULL,
    NormalizedEmail      NVARCHAR(256) NULL,
    EmailConfirmed       BIT NOT NULL,
    PasswordHash         NVARCHAR(MAX) NULL,
    SecurityStamp        NVARCHAR(MAX) NULL,
    ConcurrencyStamp     NVARCHAR(MAX) NULL,
    PhoneNumber          NVARCHAR(MAX) NULL,
    PhoneNumberConfirmed BIT NOT NULL,
    TwoFactorEnabled     BIT NOT NULL,
    LockoutEnd           DATETIMEOFFSET NULL,
    LockoutEnabled       BIT NOT NULL,
    AccessFailedCount    INT NOT NULL
);
CREATE UNIQUE INDEX UserNameIndex ON dbo.Users(NormalizedUserName) WHERE NormalizedUserName IS NOT NULL;
CREATE INDEX EmailIndex ON dbo.Users(NormalizedEmail);

CREATE TABLE dbo.UserRoles (
    UserId NVARCHAR(450) NOT NULL,
    RoleId NVARCHAR(450) NOT NULL,
    CONSTRAINT PK_UserRoles PRIMARY KEY (UserId, RoleId),
    CONSTRAINT FK_UserRoles_Users FOREIGN KEY (UserId) REFERENCES dbo.Users(Id) ON DELETE CASCADE,
    CONSTRAINT FK_UserRoles_Roles FOREIGN KEY (RoleId) REFERENCES dbo.Roles(Id) ON DELETE CASCADE
);
CREATE INDEX IX_UserRoles_RoleId ON dbo.UserRoles(RoleId);

CREATE TABLE dbo.UserClaims (
    Id         INT IDENTITY(1,1) NOT NULL CONSTRAINT PK_UserClaims PRIMARY KEY,
    UserId     NVARCHAR(450) NOT NULL,
    ClaimType  NVARCHAR(MAX) NULL,
    ClaimValue NVARCHAR(MAX) NULL,
    CONSTRAINT FK_UserClaims_Users FOREIGN KEY (UserId) REFERENCES dbo.Users(Id) ON DELETE CASCADE
);
CREATE INDEX IX_UserClaims_UserId ON dbo.UserClaims(UserId);

CREATE TABLE dbo.RoleClaims (
    Id         INT IDENTITY(1,1) NOT NULL CONSTRAINT PK_RoleClaims PRIMARY KEY,
    RoleId     NVARCHAR(450) NOT NULL,
    ClaimType  NVARCHAR(MAX) NULL,
    ClaimValue NVARCHAR(MAX) NULL,
    CONSTRAINT FK_RoleClaims_Roles FOREIGN KEY (RoleId) REFERENCES dbo.Roles(Id) ON DELETE CASCADE
);
CREATE INDEX IX_RoleClaims_RoleId ON dbo.RoleClaims(RoleId);

CREATE TABLE dbo.UserLogins (
    LoginProvider       NVARCHAR(450) NOT NULL,
    ProviderKey         NVARCHAR(450) NOT NULL,
    ProviderDisplayName NVARCHAR(MAX) NULL,
    UserId              NVARCHAR(450) NOT NULL,
    CONSTRAINT PK_UserLogins PRIMARY KEY (LoginProvider, ProviderKey),
    CONSTRAINT FK_UserLogins_Users FOREIGN KEY (UserId) REFERENCES dbo.Users(Id) ON DELETE CASCADE
);
CREATE INDEX IX_UserLogins_UserId ON dbo.UserLogins(UserId);

CREATE TABLE dbo.UserTokens (
    UserId        NVARCHAR(450) NOT NULL,
    LoginProvider NVARCHAR(450) NOT NULL,
    Name          NVARCHAR(450) NOT NULL,
    Value         NVARCHAR(MAX) NULL,
    CONSTRAINT PK_UserTokens PRIMARY KEY (UserId, LoginProvider, Name),
    CONSTRAINT FK_UserTokens_Users FOREIGN KEY (UserId) REFERENCES dbo.Users(Id) ON DELETE CASCADE
);

/* ---------- Application tables ---------- */
CREATE TABLE dbo.Datasets (
    Id                INT IDENTITY(1,1) NOT NULL CONSTRAINT PK_Datasets PRIMARY KEY,
    Name              NVARCHAR(200) NOT NULL,
    OriginalFileName  NVARCHAR(260) NOT NULL,
    StoragePath       NVARCHAR(500) NOT NULL,
    SizeBytes         BIGINT NOT NULL,
    [RowCount]        INT NOT NULL,
    ColumnCount       INT NOT NULL,
    HasLabelColumn    BIT NOT NULL,
    Status            NVARCHAR(20) NOT NULL CONSTRAINT CK_Datasets_Status CHECK (Status IN ('Validated','Invalid')),
    ValidationMessage NVARCHAR(1000) NULL,
    StatsJson         NVARCHAR(MAX) NULL,
    UploadedByUserId  NVARCHAR(450) NOT NULL,
    UploadedAt        DATETIME2 NOT NULL,
    CONSTRAINT FK_Datasets_Users FOREIGN KEY (UploadedByUserId) REFERENCES dbo.Users(Id) ON DELETE NO ACTION
);
CREATE INDEX IX_Datasets_UploadedBy ON dbo.Datasets(UploadedByUserId);

CREATE TABLE dbo.NetworkTraffic (
    Id                BIGINT IDENTITY(1,1) NOT NULL CONSTRAINT PK_NetworkTraffic PRIMARY KEY,
    DatasetId         INT NOT NULL,
    FlowIndex         INT NOT NULL,
    DestinationPort   INT NULL,
    FlowDuration      FLOAT NULL,
    TotalFwdPackets   FLOAT NULL,
    TotalBwdPackets   FLOAT NULL,
    FlowBytesPerSec   FLOAT NULL,
    FlowPacketsPerSec FLOAT NULL,
    Label             NVARCHAR(100) NULL,
    CONSTRAINT FK_NetworkTraffic_Datasets FOREIGN KEY (DatasetId) REFERENCES dbo.Datasets(Id) ON DELETE CASCADE
);
CREATE UNIQUE INDEX UX_NetworkTraffic_Dataset_Flow ON dbo.NetworkTraffic(DatasetId, FlowIndex);

CREATE TABLE dbo.Predictions (
    Id                    INT IDENTITY(1,1) NOT NULL CONSTRAINT PK_Predictions PRIMARY KEY,
    DatasetId             INT NOT NULL,
    UserId                NVARCHAR(450) NOT NULL,
    TotalFlows            INT NOT NULL,
    ThreatCount           INT NOT NULL,
    ZeroDayCount          INT NOT NULL,
    HighRiskCount         INT NOT NULL,
    MeanRisk              FLOAT NOT NULL,
    RiskHistogramJson     NVARCHAR(MAX) NOT NULL,
    ThreatTypeCountsJson  NVARCHAR(MAX) NOT NULL,
    Threshold             FLOAT NOT NULL,
    BlendWeight           FLOAT NOT NULL,
    StoredThreats         INT NOT NULL,
    Truncated             BIT NOT NULL,
    DurationMs            INT NOT NULL,
    CreatedAt             DATETIME2 NOT NULL,
    CONSTRAINT FK_Predictions_Datasets FOREIGN KEY (DatasetId) REFERENCES dbo.Datasets(Id) ON DELETE CASCADE,
    CONSTRAINT FK_Predictions_Users FOREIGN KEY (UserId) REFERENCES dbo.Users(Id) ON DELETE NO ACTION
);
CREATE INDEX IX_Predictions_Dataset ON dbo.Predictions(DatasetId);
CREATE INDEX IX_Predictions_User ON dbo.Predictions(UserId);
CREATE INDEX IX_Predictions_CreatedAt ON dbo.Predictions(CreatedAt);

CREATE TABLE dbo.RiskScores (
    Id                    BIGINT IDENTITY(1,1) NOT NULL CONSTRAINT PK_RiskScores PRIMARY KEY,
    PredictionId          INT NOT NULL,
    FlowIndex             INT NOT NULL,
    Score                 INT NOT NULL CONSTRAINT CK_RiskScores_Score CHECK (Score BETWEEN 0 AND 100),
    Severity              NVARCHAR(20) NOT NULL,
    AnomalyScore          FLOAT NOT NULL,
    SupervisedProbability FLOAT NOT NULL,
    Confidence            INT NOT NULL,
    CONSTRAINT FK_RiskScores_Predictions FOREIGN KEY (PredictionId) REFERENCES dbo.Predictions(Id) ON DELETE CASCADE
);
CREATE INDEX IX_RiskScores_Prediction ON dbo.RiskScores(PredictionId);

CREATE TABLE dbo.Threats (
    Id                    BIGINT IDENTITY(1,1) NOT NULL CONSTRAINT PK_Threats PRIMARY KEY,
    PredictionId          INT NOT NULL,
    FlowIndex             INT NOT NULL,
    ThreatType            NVARCHAR(50) NOT NULL,
    Severity              NVARCHAR(20) NOT NULL,
    RiskScore             INT NOT NULL CONSTRAINT CK_Threats_Risk CHECK (RiskScore BETWEEN 0 AND 100),
    AnomalyScore          FLOAT NOT NULL,
    SupervisedProbability FLOAT NOT NULL,
    Description           NVARCHAR(500) NOT NULL,
    DetectedAt            DATETIME2 NOT NULL,
    CONSTRAINT FK_Threats_Predictions FOREIGN KEY (PredictionId) REFERENCES dbo.Predictions(Id) ON DELETE CASCADE
);
CREATE INDEX IX_Threats_Prediction ON dbo.Threats(PredictionId);
CREATE INDEX IX_Threats_Type_Severity ON dbo.Threats(ThreatType, Severity);

CREATE TABLE dbo.Alerts (
    Id                   BIGINT IDENTITY(1,1) NOT NULL CONSTRAINT PK_Alerts PRIMARY KEY,
    ThreatId             BIGINT NOT NULL,
    Title                NVARCHAR(200) NOT NULL,
    Severity             NVARCHAR(20) NOT NULL,
    Status               NVARCHAR(20) NOT NULL CONSTRAINT CK_Alerts_Status CHECK (Status IN ('Open','Acknowledged','Resolved')),
    CreatedAt            DATETIME2 NOT NULL,
    AcknowledgedAt       DATETIME2 NULL,
    AcknowledgedByUserId NVARCHAR(450) NULL,
    CONSTRAINT FK_Alerts_Threats FOREIGN KEY (ThreatId) REFERENCES dbo.Threats(Id) ON DELETE CASCADE,
    CONSTRAINT FK_Alerts_Users FOREIGN KEY (AcknowledgedByUserId) REFERENCES dbo.Users(Id) ON DELETE NO ACTION
);
CREATE INDEX IX_Alerts_Status ON dbo.Alerts(Status, CreatedAt);
CREATE INDEX IX_Alerts_Threat ON dbo.Alerts(ThreatId);

CREATE TABLE dbo.Reports (
    Id                 INT IDENTITY(1,1) NOT NULL CONSTRAINT PK_Reports PRIMARY KEY,
    Type               NVARCHAR(30) NOT NULL CONSTRAINT CK_Reports_Type CHECK (Type IN ('Threat','Risk')),
    Title              NVARCHAR(200) NOT NULL,
    PredictionId       INT NULL,
    GeneratedByUserId  NVARCHAR(450) NOT NULL,
    ContentJson        NVARCHAR(MAX) NOT NULL,
    CreatedAt          DATETIME2 NOT NULL,
    CONSTRAINT FK_Reports_Predictions FOREIGN KEY (PredictionId) REFERENCES dbo.Predictions(Id) ON DELETE SET NULL,
    CONSTRAINT FK_Reports_Users FOREIGN KEY (GeneratedByUserId) REFERENCES dbo.Users(Id) ON DELETE NO ACTION
);
CREATE INDEX IX_Reports_User ON dbo.Reports(GeneratedByUserId);

CREATE TABLE dbo.AuditLogs (
    Id         BIGINT IDENTITY(1,1) NOT NULL CONSTRAINT PK_AuditLogs PRIMARY KEY,
    UserId     NVARCHAR(450) NULL,
    UserEmail  NVARCHAR(256) NULL,
    Action     NVARCHAR(100) NOT NULL,
    EntityType NVARCHAR(100) NULL,
    EntityId   NVARCHAR(100) NULL,
    Details    NVARCHAR(1000) NULL,
    IpAddress  NVARCHAR(64) NULL,
    Timestamp  DATETIME2 NOT NULL,
    CONSTRAINT FK_AuditLogs_Users FOREIGN KEY (UserId) REFERENCES dbo.Users(Id) ON DELETE SET NULL
);
CREATE INDEX IX_AuditLogs_Timestamp ON dbo.AuditLogs(Timestamp DESC);
CREATE INDEX IX_AuditLogs_Action ON dbo.AuditLogs(Action);
GO

/* Roles are seeded by the application on startup (Admin, Analyst, Viewer). */
