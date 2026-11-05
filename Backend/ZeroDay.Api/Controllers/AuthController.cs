using System.Security.Claims;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using ZeroDay.Api.Dtos;
using ZeroDay.Api.Models;
using ZeroDay.Api.Services;

namespace ZeroDay.Api.Controllers;

[ApiController]
public class AuthController : ControllerBase
{
    private readonly UserManager<ApplicationUser> _users;
    private readonly SignInManager<ApplicationUser> _signIn;
    private readonly IJwtService _jwt;
    private readonly IAuditService _audit;
    private readonly IConfiguration _cfg;
    private readonly ILogger<AuthController> _log;

    public AuthController(UserManager<ApplicationUser> users, SignInManager<ApplicationUser> signIn, IJwtService jwt,
                          IAuditService audit, IConfiguration cfg, ILogger<AuthController> log)
    { _users = users; _signIn = signIn; _jwt = jwt; _audit = audit; _cfg = cfg; _log = log; }

    [HttpPost("register")]
    [AllowAnonymous]
    public async Task<IActionResult> Register([FromBody] RegisterRequest req)
    {
        if (string.IsNullOrWhiteSpace(req.Email) || !req.Email.Contains('@')) return BadRequest(new { error = "A valid email is required." });
        if (string.IsNullOrWhiteSpace(req.FullName)) return BadRequest(new { error = "Full name is required." });

        var user = new ApplicationUser { UserName = req.Email.Trim(), Email = req.Email.Trim(), FullName = req.FullName.Trim() };
        var result = await _users.CreateAsync(user, req.Password ?? "");
        if (!result.Succeeded) return BadRequest(new { error = "Registration failed.", details = result.Errors.Select(e => e.Description) });

        await _users.AddToRoleAsync(user, Roles.Analyst);   // self-registered users are Analysts; Admin can change roles
        await _audit.LogAsync("Register", "User", user.Id, null, user.Id, user.Email);
        return await IssueToken(user);
    }

    [HttpPost("login")]
    [AllowAnonymous]
    public async Task<IActionResult> Login([FromBody] LoginRequest req)
    {
        var user = await _users.FindByEmailAsync(req.Email ?? "");
        if (user == null || !user.IsActive)
        {
            await _audit.LogAsync("LoginFailed", "User", null, "Unknown or inactive account: " + req.Email, null, req.Email);
            return Unauthorized(new { error = "Invalid email or password." });
        }
        var res = await _signIn.CheckPasswordSignInAsync(user, req.Password ?? "", lockoutOnFailure: true);
        if (res.IsLockedOut) return StatusCode(423, new { error = "Account locked after repeated failures. Try again later." });
        if (!res.Succeeded)
        {
            await _audit.LogAsync("LoginFailed", "User", user.Id, "Wrong password", user.Id, user.Email);
            return Unauthorized(new { error = "Invalid email or password." });
        }
        await _audit.LogAsync("Login", "User", user.Id, null, user.Id, user.Email);
        return await IssueToken(user);
    }

    [HttpPost("forgot-password")]
    [AllowAnonymous]
    public async Task<IActionResult> Forgot([FromBody] ForgotPasswordRequest req)
    {
        var user = await _users.FindByEmailAsync(req.Email ?? "");
        object? devToken = null;
        if (user != null && user.IsActive)
        {
            var token = await _users.GeneratePasswordResetTokenAsync(user);
            _log.LogInformation("Password reset requested for {Email}. Wire an email provider to deliver the token.", user.Email);
            await _audit.LogAsync("PasswordResetRequested", "User", user.Id, null, user.Id, user.Email);
            if (_cfg.GetValue<bool>("Auth:ReturnResetToken")) devToken = token;   // development only
        }
        // identical response whether or not the account exists (prevents user enumeration)
        return Ok(new { message = "If the account exists, a reset link has been sent.", resetToken = devToken });
    }

    [HttpPost("reset-password")]
    [AllowAnonymous]
    public async Task<IActionResult> Reset([FromBody] ResetPasswordRequest req)
    {
        var user = await _users.FindByEmailAsync(req.Email ?? "");
        if (user == null) return BadRequest(new { error = "Invalid or expired reset token." });
        var res = await _users.ResetPasswordAsync(user, req.Token ?? "", req.NewPassword ?? "");
        if (!res.Succeeded) return BadRequest(new { error = "Reset failed.", details = res.Errors.Select(e => e.Description) });
        await _audit.LogAsync("PasswordReset", "User", user.Id, null, user.Id, user.Email);
        return Ok(new { message = "Password updated." });
    }

    [HttpGet("me")]
    [Authorize]
    public async Task<IActionResult> Me()
    {
        var user = await _users.FindByIdAsync(User.FindFirstValue(ClaimTypes.NameIdentifier) ?? "");
        if (user == null) return Unauthorized();
        return Ok(new { user.Id, user.Email, user.FullName, roles = await _users.GetRolesAsync(user) });
    }

    private async Task<IActionResult> IssueToken(ApplicationUser user)
    {
        var roles = await _users.GetRolesAsync(user);
        var token = _jwt.Create(user, roles, out var exp);
        return Ok(new AuthResponse(token, exp, user.Email ?? "", user.FullName, roles.ToArray()));
    }
}

[ApiController]
[Route("admin")]
[Authorize(Roles = Roles.Admin)]
public class AdminController : ControllerBase
{
    private readonly UserManager<ApplicationUser> _users;
    private readonly RoleManager<ApplicationRole> _roles;
    private readonly IAuditService _audit;
    public AdminController(UserManager<ApplicationUser> users, RoleManager<ApplicationRole> roles, IAuditService audit)
    { _users = users; _roles = roles; _audit = audit; }

    [HttpGet("users")]
    public async Task<IActionResult> ListUsers()
    {
        var list = await _users.Users.OrderBy(u => u.Email).ToListAsync();
        var res = new List<object>();
        foreach (var u in list)
            res.Add(new { u.Id, u.Email, u.FullName, u.IsActive, u.CreatedAt, roles = await _users.GetRolesAsync(u) });
        return Ok(res);
    }

    [HttpGet("roles")]
    public async Task<IActionResult> ListRoles() =>
        Ok(await _roles.Roles.Select(r => new { r.Id, r.Name, r.Description }).ToListAsync());

    [HttpPut("users/{id}/role")]
    public async Task<IActionResult> SetRole(string id, [FromBody] SetRoleRequest req)
    {
        if (!await _roles.RoleExistsAsync(req.Role)) return BadRequest(new { error = "Unknown role." });
        var user = await _users.FindByIdAsync(id);
        if (user == null) return NotFound();
        if (id == User.FindFirstValue(ClaimTypes.NameIdentifier) && req.Role != Roles.Admin)
            return BadRequest(new { error = "You cannot remove your own Admin role." });
        await _users.RemoveFromRolesAsync(user, await _users.GetRolesAsync(user));
        await _users.AddToRoleAsync(user, req.Role);
        await _audit.LogAsync("RoleChanged", "User", id, $"{user.Email} -> {req.Role}");
        return Ok(new { user.Id, user.Email, role = req.Role });
    }

    [HttpPut("users/{id}/active")]
    public async Task<IActionResult> SetActive(string id, [FromQuery] bool value)
    {
        var user = await _users.FindByIdAsync(id);
        if (user == null) return NotFound();
        if (id == User.FindFirstValue(ClaimTypes.NameIdentifier)) return BadRequest(new { error = "You cannot deactivate yourself." });
        user.IsActive = value;
        await _users.UpdateAsync(user);
        await _audit.LogAsync(value ? "UserActivated" : "UserDeactivated", "User", id, user.Email);
        return Ok(new { user.Id, user.IsActive });
    }
}
