using System;

namespace ExamsPlatform.Application.Dtos;

public class AuthenticatedUserDto
{
    public int Id { get; set; }
    public string FirstName { get; set; }
    public string LastName { get; set; }
    public string Email { get; set; }
    public string AvatarUrl { get; set; }
    public bool IsEmailVerified { get; set; }
    public string Token { get; set; }
    public DateTime TokenExpirationDate { get; set; }
    public string RefreshToken { get; set; }
    public DateTime RefreshTokenExpirationDate { get; set; }
}


public class LoginRequestDto
{
    public string Email { get; set; }
    public string Password { get; set; }
}

public class RegisterRequestDto
{
    public string FirstName { get; set; }
    public string LastName { get; set; }
    public string Email { get; set; }
    public string Password { get; set; }

    // AVATAR
}

public class RefreshTokenRequestDto
{
    public string Token { get; set; }
    public string RefreshToken { get; set; }
}

public class EmailVerificationRequestDto
{
    public string Email { get; set; }
}

public class ForgetPasswordRequestDto
{
    public string Email { get; set; }
}

public class ResetPasswordRequestDto
{
    public string Token { get; set; }
    public string NewPassword { get; set; }
}

public class ChangePasswordRequestDto
{
    public string OldPassword { get; set; }
    public string NewPassword { get; set; }
}
