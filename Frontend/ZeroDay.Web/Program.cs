using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Http.Features;
using Microsoft.AspNetCore.HttpOverrides;
using ZeroDay.Web.Services;

var builder = WebApplication.CreateBuilder(args);

var port = Environment.GetEnvironmentVariable("PORT");
if (!string.IsNullOrEmpty(port)) builder.WebHost.UseUrls($"http://0.0.0.0:{port}");

builder.WebHost.ConfigureKestrel(o => o.Limits.MaxRequestBodySize = 250_000_000);
builder.Services.Configure<FormOptions>(o => o.MultipartBodyLengthLimit = 250_000_000);

builder.Services.AddControllersWithViews();
builder.Services.AddHttpContextAccessor();
builder.Services.AddHttpClient<ApiClient>(c =>
{
    var apiBase = builder.Configuration["Api:BaseUrl"] ?? "http://localhost:8080";
    if (!apiBase.Contains("://")) apiBase = "http://" + apiBase;   // Render injects host:port without a scheme
    c.BaseAddress = new Uri(apiBase);
    c.Timeout = TimeSpan.FromSeconds(builder.Configuration.GetValue<int?>("Api:TimeoutSeconds") ?? 300);
});

builder.Services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
    .AddCookie(o =>
    {
        o.LoginPath = "/Account/Login";
        o.AccessDeniedPath = "/Account/Denied";
        o.Cookie.HttpOnly = true;
        o.Cookie.SameSite = SameSiteMode.Lax;
        o.Cookie.SecurePolicy = CookieSecurePolicy.SameAsRequest;
        o.SlidingExpiration = false;       // lifetime follows the JWT expiry set at sign-in
    });
builder.Services.AddAuthorization();

var app = builder.Build();
app.UseForwardedHeaders(new ForwardedHeadersOptions { ForwardedHeaders = ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedProto });
if (!app.Environment.IsDevelopment()) app.UseExceptionHandler("/Home/Error");
app.UseStaticFiles();
app.UseRouting();
app.UseAuthentication();
app.UseAuthorization();
app.MapGet("/health", () => Results.Ok(new { status = "ok" }));
app.MapControllerRoute("default", "{controller=Home}/{action=Index}/{id?}");
app.Run();
