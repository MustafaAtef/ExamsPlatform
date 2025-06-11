using System;
using ExamsPlatform.Application.Dtos;

namespace ExamsPlatform.Application.ServiceContracts;

public interface IAuthService
{
    Task<AuthenticatedUserDto> LoginAsync(LoginRequestDto loginRequest);
    Task<AuthenticatedUserDto> RegisterAsync(RegisterRequestDto registerRequest);
    Task<AuthenticatedUserDto> RefreshTokenAsync(RefreshTokenRequestDto refreshTokenRequest);
    Task SendEmailVerificationAsync(EmailVerificationRequestDto emailVerificationRequest);
    Task<bool> VerifyEmailAsync(string token);
    Task ForgetPasswordAsync(ForgetPasswordRequestDto forgetPasswordRequestDto);
    Task<bool> VerifyPasswordResetTokenAsync(string token);
    Task ResetPasswordAsync(ResetPasswordRequestDto resetPasswordRequestDto);
    Task ChangePasswordAsync(ChangePasswordRequestDto changePasswordRequestDto);

}
