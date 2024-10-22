using UserAuthenticationApp.Models;

namespace UserAuthentication.Email
{
    public interface IEmailService
    {
        Task SendEmailAsync(string toEmail, string subject, string body);
        Task<AuthModel> VerifyEmail(string UserName, string token);
        Task<AuthModel> ResendEmailConfirmationTokenAsync(string UserName);
        Task<AuthModel> ResetPasswordRequestAsync(string email);
        Task<AuthModel> VerifyResetPasswordRequestAsync(string email, string token);
    }
}
