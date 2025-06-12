using System;
using System.Security.Claims;
using System.Security.Cryptography;
using EducationCenter.Core.RepositoryContracts;
using ExamsPlatform.Application.Dtos;
using ExamsPlatform.Application.ServiceContracts;
using ExamsPlatform.Core.Entities;
using Microsoft.AspNetCore.Http;

using Microsoft.Extensions.Configuration;

namespace ExamsPlatform.Application.Services;

public class AuthService : IAuthService
{
    private readonly IUnitOfWork _unitOfWork;
    private readonly IPasswordHasher _passwordHasher;
    private readonly IJwtService _jwtService;
    private readonly IHttpContextAccessor _httpContextAccessor;
    private readonly IEmailService _emailService;
    private readonly IConfiguration _configuration;
    public AuthService(IUnitOfWork unitOfWork, IPasswordHasher passwordHasher, IJwtService jwtService, IHttpContextAccessor httpContextAccessor, IEmailService emailService, IConfiguration configuration)
    {
        _unitOfWork = unitOfWork;
        _passwordHasher = passwordHasher;
        _jwtService = jwtService;
        _httpContextAccessor = httpContextAccessor;
        _emailService = emailService;
        _configuration = configuration;
    }

    public async Task<AuthenticatedUserDto> RegisterAsync(RegisterRequestDto registerRequest)
    {
        var user = await _unitOfWork.Users.GetAsync(u => u.Email == registerRequest.Email);
        if (user != null)
        {
            throw new Exception("User already exists with this email.");
        }
        var newUser = new User
        {
            FirstName = registerRequest.FirstName,
            LastName = registerRequest.LastName,
            Email = registerRequest.Email,
            Password = _passwordHasher.HashPassword(registerRequest.Password),
            IsEmailVerified = false,
        };

        JwtDto jwtData = _jwtService.GenerateToken(newUser);
        newUser.RefreshToken = jwtData.RefreshToken;
        newUser.RefreshTokenExpiryTime = jwtData.RefreshTokenExpirationDate;
        newUser.EmailVerificationToken = _randomToken();
        newUser.EmailVerificationTokenExpiryTime = DateTime.Now.AddMinutes(_configuration["EmailVerificationTokenExpiryMinutes"] != null ? int.Parse(_configuration["EmailVerificationTokenExpiryMinutes"] ?? "") : 15);
        _unitOfWork.Users.Add(newUser);
        await _unitOfWork.SaveChangesAsync();

        // bottelneck here because sending the email will block the regesteration response until the email is sent
        // a better approach would be to use a background service or a message queue to send the email asynchronously
        // but for simplicity we will keep it synchronous for now

        await _emailService.SendEmailVerificationAsync(newUser.Email, newUser.EmailVerificationToken, newUser.EmailVerificationTokenExpiryTime.Value);

        return new AuthenticatedUserDto
        {
            Id = newUser.Id,
            FirstName = newUser.FirstName,
            LastName = newUser.LastName,
            Email = newUser.Email,
            IsEmailVerified = false,
            Token = jwtData.Token,
            TokenExpirationDate = jwtData.TokenExpirationDate,
            RefreshToken = jwtData.RefreshToken,
            RefreshTokenExpirationDate = jwtData.RefreshTokenExpirationDate,
            AvatarUrl = newUser.AvatarUrl ?? ""
        };
    }

    public async Task<AuthenticatedUserDto> LoginAsync(LoginRequestDto loginRequest)
    {
        var user = await _unitOfWork.Users.GetAsync(u => u.Email == loginRequest.Email);
        if (user == null || !_passwordHasher.VerifyPassword(loginRequest.Password, user.Password))
        {

            throw new Exception("Invalid email or password.");
        }

        JwtDto jwtData = _jwtService.GenerateToken(user);
        user.RefreshToken = jwtData.RefreshToken;
        user.RefreshTokenExpiryTime = jwtData.RefreshTokenExpirationDate;

        await _unitOfWork.SaveChangesAsync();
        return new AuthenticatedUserDto
        {
            Id = user.Id,
            FirstName = user.FirstName,
            LastName = user.LastName,
            Email = user.Email,
            IsEmailVerified = user.IsEmailVerified,
            Token = jwtData.Token,
            TokenExpirationDate = jwtData.TokenExpirationDate,
            RefreshToken = jwtData.RefreshToken,
            RefreshTokenExpirationDate = jwtData.RefreshTokenExpirationDate,
            AvatarUrl = user.AvatarUrl ?? ""
        };
    }

    public async Task<AuthenticatedUserDto> RefreshTokenAsync(RefreshTokenRequestDto refreshTokenRequest)
    {
        var userClaims = _jwtService.ValidateJwt(refreshTokenRequest.Token);
        if (userClaims == null)
        {
            throw new Exception("Invalid refresh token.");
        }
        var userId = int.Parse(userClaims.FindFirst(ClaimTypes.NameIdentifier)?.Value ?? "-1");
        var user = await _unitOfWork.Users.GetAsync(u => u.Id == userId);
        if (user == null || user.RefreshToken != refreshTokenRequest.RefreshToken || user.RefreshTokenExpiryTime < DateTime.Now)
        {
            throw new Exception("Invalid refresh token.");
        }
        JwtDto jwtData = _jwtService.GenerateToken(user);
        user.RefreshToken = jwtData.RefreshToken;
        user.RefreshTokenExpiryTime = jwtData.RefreshTokenExpirationDate;
        await _unitOfWork.SaveChangesAsync();
        return new AuthenticatedUserDto
        {
            Id = user.Id,
            FirstName = user.FirstName,
            LastName = user.LastName,
            Email = user.Email,
            IsEmailVerified = user.IsEmailVerified,
            Token = jwtData.Token,
            TokenExpirationDate = jwtData.TokenExpirationDate,
            RefreshToken = jwtData.RefreshToken,
            RefreshTokenExpirationDate = jwtData.RefreshTokenExpirationDate,
            AvatarUrl = user.AvatarUrl ?? ""
        };
    }
    public async Task ChangePasswordAsync(ChangePasswordRequestDto changePasswordRequestDto)
    {
        var userId = int.Parse(_httpContextAccessor.HttpContext?.User.FindFirst(ClaimTypes.NameIdentifier)?.Value ?? "");
        if (userId <= 0)
        {
            throw new Exception("User not authenticated.");
        }
        var user = await _unitOfWork.Users.GetAsync(u => u.Id == userId);
        if (user == null)
        {
            throw new Exception("User not found.");
        }
        if (_passwordHasher.VerifyPassword(changePasswordRequestDto.OldPassword, user.Password) == false)
        {
            throw new Exception("Old password is incorrect.");
        }
        user.Password = _passwordHasher.HashPassword(changePasswordRequestDto.NewPassword);
        await _unitOfWork.SaveChangesAsync();
    }

    public async Task ForgetPasswordAsync(ForgetPasswordRequestDto forgetPasswordRequestDto)
    {
        var user = await _unitOfWork.Users.GetAsync(u => u.Email == forgetPasswordRequestDto.Email);
        if (user == null)
        {
            throw new Exception("User not found.");
        }

        var token = _randomToken();
        user.PasswordResetToken = token;
        user.PasswordResetTokenExpiryTime = DateTime.Now.AddMinutes(_configuration["PasswordResetTokenExpiryMinutes"] != null ? int.Parse(_configuration["PasswordResetTokenExpiryMinutes"] ?? "") : 15);
        await _unitOfWork.SaveChangesAsync();

        // Send email with reset password link
        await _emailService.SendPasswordResetAsync(user.Email, token, user.PasswordResetTokenExpiryTime.Value);
    }
    public async Task<bool> IsPasswordResetTokenValidAsync(string token)
    {
        var user = await _unitOfWork.Users.GetAsync(u => u.PasswordResetToken == token);
        if (user == null || user.PasswordResetTokenExpiryTime < DateTime.Now)
        {
            return false;
        }
        return true;
    }
    public async Task ResetPasswordAsync(ResetPasswordRequestDto resetPasswordRequestDto)
    {
        var user = await _unitOfWork.Users.GetAsync(u => u.PasswordResetToken == resetPasswordRequestDto.Token);
        if (user == null || user.PasswordResetTokenExpiryTime < DateTime.Now)
        {
            throw new Exception("Invalid or expired password reset token.");
        }
        user.Password = _passwordHasher.HashPassword(resetPasswordRequestDto.NewPassword);
        user.PasswordResetToken = null;
        user.PasswordResetTokenExpiryTime = null;
        await _unitOfWork.SaveChangesAsync();
    }


    public async Task SendEmailVerificationAsync(EmailVerificationRequestDto emailVerificationRequest)
    {
        var user = await _unitOfWork.Users.GetAsync(u => u.Email == emailVerificationRequest.Email);
        if (user == null)
        {
            throw new Exception("User not found.");
        }
        if (user.IsEmailVerified)
        {
            throw new Exception("Email is already verified.");
        }

        user.EmailVerificationToken = _randomToken();
        user.EmailVerificationTokenExpiryTime = DateTime.Now.AddMinutes(_configuration["EmailVerificationTokenExpiryMinutes"] != null ? int.Parse(_configuration["EmailVerificationTokenExpiryMinutes"] ?? "") : 15);
        await _unitOfWork.SaveChangesAsync();
        await _emailService.SendEmailVerificationAsync(user.Email, user.EmailVerificationToken, user.EmailVerificationTokenExpiryTime.Value);
    }

    public async Task<bool> VerifyEmailAsync(string token)
    {
        var user = await _unitOfWork.Users.GetAsync(u => u.EmailVerificationToken == token);
        if (user == null || user.EmailVerificationTokenExpiryTime < DateTime.Now)
        {
            return false;
        }
        user.IsEmailVerified = true;
        user.EmailVerificationToken = null;
        user.EmailVerificationTokenExpiryTime = null;
        await _unitOfWork.SaveChangesAsync();
        return true;
    }


    private string _randomToken(int size = 32)
    {
        using var randomNumberGenerator = RandomNumberGenerator.Create();
        var randomBytes = new byte[size];
        randomNumberGenerator.GetBytes(randomBytes);
        return Convert.ToHexString(randomBytes);
    }
}
