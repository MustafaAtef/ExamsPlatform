using System;

namespace ExamsPlatform.Application.ServiceContracts;

public interface IPasswordHasher
{
    string HashPassword(string password);
    bool VerifyPassword(string password, string hashedPassword);
}
