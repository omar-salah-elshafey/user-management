using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using UserAuthentication.Email;
using UserAuthentication.Models;
using UserAuthentication.Services;
using UserAuthenticationApp.Models;

namespace UserAuthentication.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly IConfiguration _configuration;
        public readonly IAuthService _authService;
        public readonly ITokenService _tokenService;
        private readonly ILogger<AuthController> _logger;

        public AuthController
            (UserManager<ApplicationUser> userManager, RoleManager<IdentityRole> roleManager,
            IConfiguration configuration, IAuthService authService, ITokenService tokenService)
        {
            _userManager = userManager;
            _roleManager = roleManager;
            _configuration = configuration;
            _authService = authService;
            _tokenService = tokenService;
        }
        //[Authorize(Roles ="Admin")]
        [HttpPost("register")]
        public async Task<IActionResult> RegisterAsync([FromBody]RegisterUser registerUser)
        {
            if (!ModelState.IsValid)
                return BadRequest(ModelState);
            var result = await _authService.RegisterAsync(registerUser);

            if (!result.IsAuthenticated)
                return BadRequest(result.Message);

            return Ok(new
            {
                result.Email,
                result.Username,
                result.Message,
                //result.Roles,
                result.IsAuthenticated,
                result.IsConfirmed
            });
        }

        [HttpPost("login")]
        public async Task<IActionResult> LoginAsync([FromBody] LoginModel model)
        {
            if (!ModelState.IsValid)
                return BadRequest(ModelState);
            var result = await _authService.LoginAsync(model);

            if (!result.IsAuthenticated)
                return BadRequest(result.Message);

            if (!string.IsNullOrEmpty(result.RefreshToken))
            {
                SetRefreshTokenCookie(result.RefreshToken, result.RefreshTokenExpiresOn);
            }

            return Ok(new
            {
                result.Token,
                result.ExpiresAt,
                result.RefreshToken,
                result.RefreshTokenExpiresOn,
            });
        }

        [HttpGet("refreshtoken")]
        public async Task<IActionResult> RefreshToken()
        {
            var refreshToken = Request.Cookies["refreshToken"];

            var result = await _tokenService.RefreshTokenAsync(refreshToken);

            if (!result.IsAuthenticated)
                return BadRequest(result);
            SetRefreshTokenCookie(result.RefreshToken, result.RefreshTokenExpiresOn);
            return Ok(new
            {
                result.Token,
                result.ExpiresAt,
                result.RefreshToken,
                result.RefreshTokenExpiresOn,
            });
        }

        [HttpPost("reset-password")]
        public async Task<IActionResult> ResetPasswordAsync(string email, string token, string newPassword)
        {
            if (!ModelState.IsValid)
                return BadRequest(ModelState);
            var result = await _authService.ResetPasswordAsync(email, token, newPassword);
            return Ok(result.Message);
        }

        [HttpPost("change-password")]
        public async Task<IActionResult> ChangePasswordAsync(string email, string currentPassword, string newPassword)
        {
            if (!ModelState.IsValid)
                return BadRequest(ModelState);
            var result = await _authService.ChangePasswordAsync(email, currentPassword, newPassword);
            return Ok(result.Message);
        }

        [HttpPost("add-role")]
        [Authorize(Roles = "Admin")]
        public async Task<IActionResult> AddRoleAsync(string role, string userName)
        {
            if (!ModelState.IsValid)
                return BadRequest(ModelState);
            var user = await _userManager.FindByNameAsync(userName);
            var result = await _authService.AddRoleAsync(role, userName);

            if (!result.Equals($"User {user.UserName} has been assignd to Role {role} Successfully :)"))
                return BadRequest(result);

            return Ok($"The user: {userName} has been assignd to Role {role} Successfully");
        }

        [HttpGet("get-users")]
        [Authorize(Roles = "Admin")]
        public async Task<IActionResult> GetUsers()
        {
            var users = await _authService.GetUSersAsync();
            if (users == null || !users.Any())
                return NotFound("No users found!");
            return Ok(users);
        }

        [HttpDelete("delete-user")]
        [Authorize(Roles = "Admin")]
        public async Task<IActionResult> DeleteUserAsync(string UserName)
        {
            if (!ModelState.IsValid)
                return BadRequest(ModelState);
            var result = await _authService.DeleteUserAsync(UserName);
            if (result.Message.Contains("isn't found") || result.Message.Contains("An error occurred"))
                return BadRequest(result.Message);
            return Ok($"User with UserName: '{UserName}' has been Deleted successfully");
        }

        //[HttpPost("logout")]
        //public async Task<IActionResult> Logout()
        //{
        //    await _authService.LogoutAsync();
        //    return Ok(new { message = "Successfully logged out" });
        //}

        private void SetRefreshTokenCookie(string refreshToken, DateTime ex)
        {
            var cookieOptions = new CookieOptions
            {
                HttpOnly = true,
                Expires = ex.ToLocalTime(),
                Secure = true,    // Set this in production when using HTTPS
                SameSite = SameSiteMode.Strict
            };
            Response.Cookies.Append("refreshToken", refreshToken, cookieOptions);
        }
    }
}
