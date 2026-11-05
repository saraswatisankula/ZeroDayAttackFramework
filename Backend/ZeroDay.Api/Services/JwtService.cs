using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Microsoft.IdentityModel.Tokens;
using ZeroDay.Api.Models;

namespace ZeroDay.Api.Services;

public class JwtOptions
{
    public string Key { get; set; } = "";
    public string Issuer { get; set; } = "ZeroDayApi";
    public string Audience { get; set; } = "ZeroDayClients";
    public int ExpiryMinutes { get; set; } = 120;
}

public interface IJwtService
{
    string Create(ApplicationUser user, IEnumerable<string> roles, out DateTime expiresAt);
}

public class JwtService : IJwtService
{
    private readonly JwtOptions _opt;
    public JwtService(IConfiguration cfg) => _opt = cfg.GetSection("Jwt").Get<JwtOptions>() ?? new JwtOptions();

    public string Create(ApplicationUser user, IEnumerable<string> roles, out DateTime expiresAt)
    {
        expiresAt = DateTime.UtcNow.AddMinutes(_opt.ExpiryMinutes);
        var claims = new List<Claim>
        {
            new(JwtRegisteredClaimNames.Sub, user.Id),
            new(ClaimTypes.NameIdentifier, user.Id),
            new(JwtRegisteredClaimNames.Email, user.Email ?? ""),
            new(ClaimTypes.Name, user.FullName),
            new(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
        };
        claims.AddRange(roles.Select(r => new Claim(ClaimTypes.Role, r)));
        var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_opt.Key));
        var token = new JwtSecurityToken(_opt.Issuer, _opt.Audience, claims, expires: expiresAt,
            signingCredentials: new SigningCredentials(key, SecurityAlgorithms.HmacSha256));
        return new JwtSecurityTokenHandler().WriteToken(token);
    }
}
