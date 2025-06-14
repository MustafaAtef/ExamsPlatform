﻿

using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using ExamsPlatform.Application.Dtos;
using ExamsPlatform.Application.ServiceContracts;
using ExamsPlatform.Core.Entities;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;

namespace ExamsPlatform.Infrastructure.Auth;

public class JwtService : IJwtService
{
    private readonly JwtOptions _jwtOptions;

    public JwtService(IOptions<JwtOptions> jwtOptions)
    {
        _jwtOptions = jwtOptions.Value;
    }

    public JwtDto GenerateToken(User user)
    {
        var claims = new[]
        {
            new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
            new Claim(ClaimTypes.NameIdentifier, user.Id.ToString()),
        };

        var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_jwtOptions.SigningKey));
        var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

        var jwtSecurityToken = new JwtSecurityToken(
            issuer: _jwtOptions.Issuer,
            audience: _jwtOptions.Audience,
            claims: claims,
            expires: DateTime.Now.AddMinutes(_jwtOptions.Lifetime),
            signingCredentials: creds
        );
        var token = new JwtSecurityTokenHandler().WriteToken(jwtSecurityToken);
        return new()
        {
            Token = token,
            TokenExpirationDate = DateTime.Now.AddMinutes(_jwtOptions.Lifetime),
            RefreshToken = GenerateRefreshToken(),
            RefreshTokenExpirationDate = DateTime.Now.AddMinutes(_jwtOptions.RefreshTokenLifetime)
        };
    }

    public ClaimsPrincipal? ValidateJwt(string token)
    {
        var tokenValidationParameters = new TokenValidationParameters()
        {
            ValidateIssuer = true,
            ValidIssuer = _jwtOptions.Issuer,
            ValidateAudience = true,
            ValidAudience = _jwtOptions.Audience,
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_jwtOptions.SigningKey)),
            ValidateLifetime = false
        };

        var tokenHandler = new JwtSecurityTokenHandler() { MapInboundClaims = false };
        try
        {
            return tokenHandler.ValidateToken(token, tokenValidationParameters, out var validatedToken);
        }
        catch
        {
            return null;
        }
    }

    private string GenerateRefreshToken()
    {
        byte[] randomBytes = new byte[32];
        using var randomNumberGenerator = RandomNumberGenerator.Create();
        randomNumberGenerator.GetBytes(randomBytes);
        return Convert.ToBase64String(randomBytes);
    }
}
