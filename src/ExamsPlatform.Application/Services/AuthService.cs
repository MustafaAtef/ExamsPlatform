using System;
using EducationCenter.Core.RepositoryContracts;
using ExamsPlatform.Application.Dtos;
using ExamsPlatform.Application.ServiceContracts;
using ExamsPlatform.Core.Entities;

namespace ExamsPlatform.Application.Services;

public class AuthService : IAuthService
{
    private readonly IUnitOfWork _unitOfWork;
    private readonly IPasswordHasher _passwordHasher;
    private readonly IJwtService _jwtService;
    public AuthService(IUnitOfWork unitOfWork, IPasswordHasher passwordHasher, IJwtService jwtService)
    {
        _unitOfWork = unitOfWork;
        _passwordHasher = passwordHasher;
        _jwtService = jwtService;
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
        // handle sending the email to verifiy the account

        _unitOfWork.Users.Add(newUser);
        await _unitOfWork.SaveChangesAsync();
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
    public Task ChangePasswordAsync(ChangePasswordRequestDto changePasswordRequestDto)
    {
        throw new NotImplementedException();
    }

    public Task ForgetPasswordAsync(ForgetPasswordRequestDto forgetPasswordRequestDto)
    {
        throw new NotImplementedException();
    }

    public Task<AuthenticatedUserDto> LoginAsync(LoginRequestDto loginRequest)
    {
        throw new NotImplementedException();
    }

    public Task<AuthenticatedUserDto> RefreshTokenAsync(RefreshTokenRequestDto refreshTokenRequest)
    {
        throw new NotImplementedException();
    }


    public Task ResetPasswordAsync(ResetPasswordRequestDto resetPasswordRequestDto)
    {
        throw new NotImplementedException();
    }

    public Task SendEmailVerificationAsync(EmailVerificationRequestDto emailVerificationRequest)
    {
        throw new NotImplementedException();
    }

    public Task<bool> VerifyEmailAsync(string token)
    {
        throw new NotImplementedException();
    }

    public Task<bool> VerifyPasswordResetTokenAsync(string token)
    {
        throw new NotImplementedException();
    }
}
