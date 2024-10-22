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

        public AuthController
            (UserManager<ApplicationUser> userManager, RoleManager<IdentityRole> roleManager,
            IConfiguration configuration, IAuthService authService)
        {
            _userManager = userManager;
            _roleManager = roleManager;
            _configuration = configuration;
            _authService = authService;
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
        public async Task<IActionResult> LoginAsync([FromBody] LoginModel loginModel)
        {
            if (!ModelState.IsValid)
                return BadRequest(ModelState);
            var result = await _authService.LoginAsync(loginModel);

            if (!result.IsAuthenticated)
                return BadRequest(result.Message);

            return Ok(result.Token);
        }

        [HttpPost("addrole")]
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

        [HttpDelete("delete-user")]
        [Authorize(Roles = "Admin")]
        public async Task<IActionResult> DeleteUser(string UserName)
        {
            if (!ModelState.IsValid)
                return BadRequest(ModelState);
            var result = await _authService.DeleteUserAsync(UserName);
            if (result.Message.Contains("isn't found") || result.Message.Contains("An error occurred"))
                return BadRequest(result.Message);
            return Ok($"User with UserName: '{UserName}' has been Deleted successfully");
        }

        [HttpPost("reset-password")]
        public async Task<IActionResult> ResetPasswordAsync(string email, string token, string newPassword)
        {
            if (!ModelState.IsValid)
                return BadRequest(ModelState);
            var result = await _authService.ResetPasswordAsync(email, token, newPassword);
            return Ok(result.Message);
        }


    }
}
