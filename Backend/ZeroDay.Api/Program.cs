using System.Text;
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi.Models;
using ZeroDay.Api.Data;
using ZeroDay.Api.Models;
using ZeroDay.Api.Services;

var builder = WebApplication.CreateBuilder(args);

// Render (and most PaaS hosts) provide the port in $PORT
var port = Environment.GetEnvironmentVariable("PORT");
if (!string.IsNullOrEmpty(port)) builder.WebHost.UseUrls($"http://0.0.0.0:{port}");

var cfg = builder.Configuration;
var jwtKey = cfg["Jwt:Key"];
if (string.IsNullOrWhiteSpace(jwtKey) || jwtKey.Length < 32)
    throw new InvalidOperationException("Set Jwt__Key to a random secret of at least 32 characters.");

// ---------- database + identity
builder.Services.AddDbContext<ApplicationDbContext>(o =>
    o.UseSqlServer(cfg.GetConnectionString("Default"), sql => sql.EnableRetryOnFailure(5, TimeSpan.FromSeconds(5), null)));

builder.Services.AddIdentityCore<ApplicationUser>(o =>
    {
        o.Password.RequiredLength = 8;
        o.Password.RequireDigit = true;
        o.Password.RequireUppercase = true;
        o.Password.RequireLowercase = true;
        o.Password.RequireNonAlphanumeric = false;
        o.User.RequireUniqueEmail = true;
        o.Lockout.MaxFailedAccessAttempts = 5;
        o.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(15);
    })
    .AddRoles<ApplicationRole>()
    .AddEntityFrameworkStores<ApplicationDbContext>()
    .AddSignInManager()
    .AddDefaultTokenProviders();

// ---------- JWT
builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(o =>
    {
        o.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true, ValidIssuer = cfg["Jwt:Issuer"],
            ValidateAudience = true, ValidAudience = cfg["Jwt:Audience"],
            ValidateIssuerSigningKey = true, IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtKey)),
            ValidateLifetime = true, ClockSkew = TimeSpan.FromMinutes(1)
        };
    });
builder.Services.AddAuthorization();

// ---------- app services
builder.Services.AddHttpContextAccessor();
builder.Services.AddScoped<IJwtService, JwtService>();
builder.Services.AddScoped<IAuditService, AuditService>();
builder.Services.AddScoped<DatasetService>();
builder.Services.AddScoped<PredictionService>();
builder.Services.AddScoped<ReportService>();
builder.Services.AddHttpClient<MlClient>(c =>
{
    var mlBase = cfg["Ml:BaseUrl"] ?? "http://localhost:8000";
    if (!mlBase.Contains("://")) mlBase = "http://" + mlBase;   // Render injects host:port without a scheme
    c.BaseAddress = new Uri(mlBase);
    c.Timeout = TimeSpan.FromSeconds(cfg.GetValue<int?>("Ml:TimeoutSeconds") ?? 300);
});

builder.Services.AddControllers();
builder.Services.AddCors(o => o.AddDefaultPolicy(p =>
{
    var origins = cfg.GetSection("Cors:Origins").Get<string[]>() ?? Array.Empty<string>();
    if (origins.Length > 0) p.WithOrigins(origins).AllowAnyHeader().AllowAnyMethod();
}));

builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen(o =>
{
    o.SwaggerDoc("v1", new OpenApiInfo { Title = "Zero-Day Attack Framework API", Version = "v1" });
    o.AddSecurityDefinition("Bearer", new OpenApiSecurityScheme
    {
        Name = "Authorization", Type = SecuritySchemeType.Http, Scheme = "bearer", BearerFormat = "JWT",
        In = ParameterLocation.Header, Description = "Paste the JWT returned by /login"
    });
    o.AddSecurityRequirement(new OpenApiSecurityRequirement
    {
        { new OpenApiSecurityScheme { Reference = new OpenApiReference { Type = ReferenceType.SecurityScheme, Id = "Bearer" } }, Array.Empty<string>() }
    });
});

var app = builder.Build();

app.UseForwardedHeaders(new ForwardedHeadersOptions { ForwardedHeaders = ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedProto });
app.UseExceptionHandler(a => a.Run(async ctx =>
{
    ctx.Response.StatusCode = 500;
    ctx.Response.ContentType = "application/json";
    await ctx.Response.WriteAsJsonAsync(new { error = "Unexpected server error." });
}));
app.UseSwagger();
app.UseSwaggerUI();
app.UseCors();
app.UseAuthentication();
app.UseAuthorization();
app.MapControllers();
app.MapGet("/health", async (ApplicationDbContext db) =>
    Results.Ok(new { status = "ok", database = await db.Database.CanConnectAsync() }));
app.MapGet("/", () => Results.Redirect("/swagger"));

await InitialiseAsync(app);
app.Run();

// ---------- schema creation + seeding (retries while SQL Server container is starting)
static async Task InitialiseAsync(WebApplication app)
{
    var log = app.Logger;
    using var scope = app.Services.CreateScope();
    var sp = scope.ServiceProvider;
    var db = sp.GetRequiredService<ApplicationDbContext>();

    for (int attempt = 1; ; attempt++)
    {
        try
        {
            if (app.Configuration.GetValue("Database:AutoCreate", true)) await db.Database.EnsureCreatedAsync();
            break;
        }
        catch (Exception ex) when (attempt < 15)
        {
            log.LogWarning("Database not ready (attempt {Attempt}/15): {Msg}", attempt, ex.Message);
            await Task.Delay(TimeSpan.FromSeconds(4));
        }
    }

    var roles = sp.GetRequiredService<RoleManager<ApplicationRole>>();
    var descriptions = new Dictionary<string, string>
    {
        [Roles.Admin] = "Full access incl. user management and audit logs",
        [Roles.Analyst] = "Upload datasets, run predictions, manage alerts and reports",
        [Roles.Viewer] = "Read-only access to dashboards, threats, alerts and reports"
    };
    foreach (var (name, desc) in descriptions)
        if (!await roles.RoleExistsAsync(name)) await roles.CreateAsync(new ApplicationRole(name) { Description = desc });

    var email = app.Configuration["Seed:AdminEmail"];
    var pwd = app.Configuration["Seed:AdminPassword"];
    if (!string.IsNullOrWhiteSpace(email) && !string.IsNullOrWhiteSpace(pwd))
    {
        var users = sp.GetRequiredService<UserManager<ApplicationUser>>();
        if (await users.FindByEmailAsync(email) == null)
        {
            var admin = new ApplicationUser { UserName = email, Email = email, FullName = "System Administrator", EmailConfirmed = true };
            var res = await users.CreateAsync(admin, pwd);
            if (res.Succeeded) await users.AddToRoleAsync(admin, Roles.Admin);
            else log.LogError("Admin seed failed: {Errors}", string.Join("; ", res.Errors.Select(e => e.Description)));
        }
    }
}
