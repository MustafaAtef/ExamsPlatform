﻿namespace ExamsPlatform.Infrastructure.Auth;

public class JwtOptions
{
    public string Issuer { get; set; }
    public string Audience { get; set; }
    public int Lifetime { get; set; }
    public int RefreshTokenLifetime { get; set; }
    public string SigningKey { get; set; }
}
