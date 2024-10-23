
using MailKit.Net.Smtp;
using MimeKit;
using System.Threading.Tasks;
using Microsoft.Extensions.Configuration;
using Microsoft.AspNetCore.Identity;
using UserAuthenticationApp.Models;
using Microsoft.Extensions.Options;
using UserAuthentication.Models;
namespace UserAuthentication.Email
{
    public class EmailService : IEmailService
    {
        private readonly IConfiguration _config;
        private readonly UserManager<ApplicationUser> _userManager;
        //private readonly IOptions<DataProtectionTokenProviderOptions> _tokenProviderOptions;

        public EmailService(IConfiguration config, UserManager<ApplicationUser> userManager)
        {
            _config = config;
            _userManager = userManager;
        }

        public async Task SendEmailAsync(string toEmail, string subject, string body)
        {
            var email = new MimeMessage();
            email.From.Add(MailboxAddress.Parse(_config["EmailSettings:From"]));
            email.To.Add(MailboxAddress.Parse(toEmail));
            email.Subject = subject;

            var builder = new BodyBuilder { HtmlBody = body };
            email.Body = builder.ToMessageBody();

            using var smtp = new SmtpClient();
            await smtp.ConnectAsync(_config["EmailSettings:SmtpServer"], int.Parse(_config["EmailSettings:Port"]),
                MailKit.Security.SecureSocketOptions.StartTls);
            await smtp.AuthenticateAsync(_config["EmailSettings:Username"], _config["EmailSettings:Password"]);
            await smtp.SendAsync(email);
            await smtp.DisconnectAsync(true);
        }

        public async Task<AuthModel> VerifyEmail(ConfirmEmailModel confirmEmail)
        {

            if (string.IsNullOrEmpty(confirmEmail.Email) || string.IsNullOrEmpty(confirmEmail.Token))
                return new AuthModel { IsConfirmed = false, Message = "User ID and token are required." };

            var user = await _userManager.FindByEmailAsync(confirmEmail.Email);
            if (user == null)
                return new AuthModel { IsConfirmed = false, Message = "User not found." };
            var result = await _userManager.ConfirmEmailAsync(user, confirmEmail.Token);
            if (!result.Succeeded)
                return new AuthModel { IsConfirmed = false, Message = "Token is not valid!" };

            return new AuthModel { IsConfirmed = true, Message = "Your Email has been confirmed successfully :) " };
        }

        public async Task<AuthModel> ResendEmailConfirmationTokenAsync(string UserName)
        {
            var user = await _userManager.FindByNameAsync(UserName);
            if (user == null)
                return new AuthModel { IsConfirmed = false, Message = "User not found." };

            if (await _userManager.IsEmailConfirmedAsync(user))
                return new AuthModel { IsConfirmed = true, Message = "Email is already confirmed." };

            // Generate new token
            var token = await _userManager.GenerateEmailConfirmationTokenAsync(user);
            //var expirationTime = _tokenProviderOptions.Value.TokenLifespan.TotalMinutes;
            // Send the new token via email
            await SendEmailAsync(user.Email, "Email Verification Code",
                $"Hello {user.UserName}, \n Use this new token to verify your Email: {token}\n This code is Valid only for 5 Minutes.");

            return new AuthModel { IsConfirmed = false, Message = "A new verification email has been sent." };
        }

        public async Task<AuthModel> ResetPasswordRequestAsync(string email)
        {

            var user = await _userManager.FindByEmailAsync(email);
            if (user is null)
                return new AuthModel { Message = "The Email you Provided is not Correct!" };
            //generating the token to verify the user's email
            var token = await _userManager.GeneratePasswordResetTokenAsync(user);

            // Dynamically get the expiration time from the options
            //var expirationTime = _tokenProviderOptions.Value.TokenLifespan.TotalMinutes;

            await SendEmailAsync(email, "Password Reset Code.",
                $"Hello {user.UserName}, \n Use this new token to Reset your Password: {token}\n This code is Valid only for 5 Minutes.");
            return new AuthModel { Message = "A Password Reset Code has been sent to your Email!" };
        }

        public async Task<AuthModel> VerifyResetPasswordRequestAsync(ConfirmEmailModel verifyREsetPassword)
        {

            if (string.IsNullOrEmpty(verifyREsetPassword.Email) || string.IsNullOrEmpty(verifyREsetPassword.Token))
                return new AuthModel { ISPasswordResetRequestVerified = false, Message = "UserName and token are required." };

            var user = await _userManager.FindByEmailAsync(verifyREsetPassword.Email);
            if (user == null)
                return new AuthModel { ISPasswordResetRequestVerified = false, Message = "User not found." };
            var result = await _userManager.VerifyUserTokenAsync(user, _userManager.Options.Tokens.PasswordResetTokenProvider, "ResetPassword", verifyREsetPassword.Token);
            if (!result)
                return new AuthModel { ISPasswordResetRequestVerified = false, Message = "Token is not valid!" };

            return new AuthModel { ISPasswordResetRequestVerified = true, Message = "Your Password reset request is verified." };
        }
    }

}
