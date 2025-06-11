using System;

namespace ExamsPlatform.Application.ServiceContracts;

public interface IEmailService
{
    Task SendAsync();
}
