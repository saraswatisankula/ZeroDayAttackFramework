using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using ZeroDay.Web.Services;

namespace ZeroDay.Web.Controllers;

[AllowAnonymous]
public class AccountController : Controller
{
    private readonly ApiClient _api;
    public AccountController(ApiClient api) => _api = api;

    [HttpGet] public IActionResult Login(string? returnUrl = null) { ViewData["ReturnUrl"] = returnUrl; return View(); }
    [HttpGet] public IActionResult Register() => View();
    [HttpGet] public IActionResult Forgot() => View();
    [HttpGet] public IActionResult Reset(string? email = null) { ViewData["Email"] = email; return View(); }
    [HttpGet] public IActionResult Denied() => View();

    [HttpPost, ValidateAntiForgeryToken]
    public async Task<IActionResult> Login(string email, string password, string? returnUrl = null)
    {
        var r = await _api.PostJsonAsync("/login", new { email, password });
        if (!r.Ok) { ViewData["Error"] = r.Error; ViewData["ReturnUrl"] = returnUrl; return View(); }
        await SignIn(r.Json);
        return !string.IsNullOrEmpty(returnUrl) && Url.IsLocalUrl(returnUrl) ? Redirect(returnUrl) : RedirectToAction("Index", "Home");
    }

    [HttpPost, ValidateAntiForgeryToken]
    public async Task<IActionResult> Register(string fullName, string email, string password, string confirmPassword)
    {
        if (password != confirmPassword) { ViewData["Error"] = "Passwords do not match."; return View(); }
        var r = await _api.PostJsonAsync("/register", new { fullName, email, password });
        if (!r.Ok) { ViewData["Error"] = r.Error; return View(); }
        await SignIn(r.Json);
        return RedirectToAction("Index", "Home");
    }

    [HttpPost, ValidateAntiForgeryToken]
    public async Task<IActionResult> Forgot(string email)
    {
        var r = await _api.PostJsonAsync("/forgot-password", new { email });
        if (!r.Ok) { ViewData["Error"] = r.Error; return View(); }
        TempData["Success"] = "If the account exists, reset instructions have been sent.";
        var devToken = r.Json.S("resetToken");
        if (devToken.Length > 0) TempData["DevToken"] = devToken;       // only present when the API runs with Auth__ReturnResetToken=true
        return RedirectToAction(nameof(Reset), new { email });
    }

    [HttpPost, ValidateAntiForgeryToken]
    public async Task<IActionResult> Reset(string email, string token, string newPassword)
    {
        var r = await _api.PostJsonAsync("/reset-password", new { email, token, newPassword });
        if (!r.Ok) { ViewData["Error"] = r.Error; ViewData["Email"] = email; return View(); }
        TempData["Success"] = "Password updated. Please sign in.";
        return RedirectToAction(nameof(Login));
    }

    [HttpPost, ValidateAntiForgeryToken, Authorize]
    public async Task<IActionResult> Logout()
    {
        await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
        return RedirectToAction(nameof(Login));
    }

    private async Task SignIn(System.Text.Json.JsonElement auth)
    {
        var claims = new List<Claim>
        {
            new(ClaimTypes.Name, auth.S("fullName")),
            new(ClaimTypes.Email, auth.S("email")),
            new("access_token", auth.S("token"))
        };
        claims.AddRange(auth.A("roles").Select(x => new Claim(ClaimTypes.Role, x.ToString())));
        var expires = DateTime.TryParse(auth.S("expiresAt"), null, System.Globalization.DateTimeStyles.RoundtripKind, out var e)
            ? e : DateTime.UtcNow.AddHours(2);
        await HttpContext.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme,
            new ClaimsPrincipal(new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme)),
            new AuthenticationProperties { IsPersistent = false, ExpiresUtc = new DateTimeOffset(expires.ToUniversalTime()) });
    }
}
