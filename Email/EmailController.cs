using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using UserAuthentication.Models;
using UserAuthentication.Services;
using UserAuthenticationApp.Models;

namespace UserAuthentication.Email
{
    [Route("api/[controller]")]
    [ApiController]
    public class EmailController : ControllerBase
    {
        private readonly IEmailService _emailService;
        public readonly IAuthService _authService;
        public EmailController(IEmailService emailService, IAuthService authService)
        {
            _emailService = emailService;
            _authService = authService;
        }

        [HttpPost("confirm-email")]
        public async Task<IActionResult> VerifyEmail(ConfirmEmailModel confirmEmail)
        {
            // Validate the input fields (UserName and token)
            if (string.IsNullOrEmpty(confirmEmail.Email) || string.IsNullOrEmpty(confirmEmail.Token))
                return BadRequest(new { Message = "User ID and token are required." });

            // Call the service to verify the email
            var result = await _emailService.VerifyEmail(confirmEmail);

            // Check if the verification failed
            if (!result.IsConfirmed)
                return BadRequest(new { result.Message });

            // Return a success response
            return Ok(new
            {
                result.Message,
                result.IsConfirmed
            });
        }

        [HttpPost("resend-confirmation-email")]
        public async Task<IActionResult> ResendConfirmationEmail(string UserName)
        {
            var result = await _emailService.ResendEmailConfirmationTokenAsync(UserName);

            return Ok(result.Message);
        }

        [HttpPost("reset-password-request")]
        public async Task<IActionResult> ResetPasswordRequestAsync(string email)
        {
            if (!ModelState.IsValid)
                return BadRequest(ModelState);
            var result = await _emailService.ResetPasswordRequestAsync(email);
            return Ok(result.Message);
        }

        [HttpPost("verify-password-reset-token")]
        public async Task<IActionResult> VerifyResetPasswordRequestAsync(ConfirmEmailModel verifyREsetPassword)
        {
            if (!ModelState.IsValid)
                return BadRequest(ModelState);
            // Call the service to verify the email
            var result = await _emailService.VerifyResetPasswordRequestAsync(verifyREsetPassword);

            // Check if the verification failed
            if (!result.ISPasswordResetRequestVerified)
                return BadRequest(new { result.Message });
            return Ok(new {result.Message, result.ISPasswordResetRequestVerified });
        }
    }
}
