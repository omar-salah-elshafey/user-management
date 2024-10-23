using UserAuthentication.Models;
using UserAuthenticationApp.Models;

namespace UserAuthentication.Email
{
    public interface IEmailService
    {
        Task SendEmailAsync(string toEmail, string subject, string body);
        Task<AuthModel> VerifyEmail(ConfirmEmailModel confirmEmail);
        Task<AuthModel> ResendEmailConfirmationTokenAsync(string UserName);
        Task<AuthModel> ResetPasswordRequestAsync(string email);
        Task<AuthModel> VerifyResetPasswordRequestAsync(ConfirmEmailModel verifyREsetPassword);
    }
}
