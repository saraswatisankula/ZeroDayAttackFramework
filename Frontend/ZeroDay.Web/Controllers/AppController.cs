using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using ZeroDay.Web.Services;

namespace ZeroDay.Web.Controllers;

[Authorize]
public abstract class AppController : Controller
{
    protected readonly ApiClient Api;
    protected AppController(ApiClient api) => Api = api;

    /// <summary>Returns a redirect when the API says the session expired (401); null otherwise.</summary>
    protected async Task<IActionResult?> SessionExpired(ApiResult r)
    {
        if (r.Status != 401) return null;
        await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
        TempData["Error"] = "Your session expired. Please sign in again.";
        return RedirectToAction("Login", "Account");
    }

    protected void Flash(ApiResult r, string okMessage)
    {
        if (r.Ok) TempData["Success"] = okMessage; else TempData["Error"] = r.Error ?? "Request failed.";
    }
}
