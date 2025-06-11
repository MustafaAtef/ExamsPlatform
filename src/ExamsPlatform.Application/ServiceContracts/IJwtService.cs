

using System.Security.Claims;
using ExamsPlatform.Application.Dtos;
using ExamsPlatform.Core.Entities;

namespace ExamsPlatform.Application.ServiceContracts;

public interface IJwtService
{
    JwtDto GenerateToken(User user);
    ClaimsPrincipal? ValidateJwt(string token);
}
