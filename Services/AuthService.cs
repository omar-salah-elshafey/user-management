using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using UserAuthentication.Email;
using UserAuthentication.Models;
using UserAuthenticationApp.Models;

namespace UserAuthentication.Services
{
    public class AuthService : IAuthService
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly RoleManager<IdentityRole> _roleManager;
        //private readonly JWT _jwt;
        private readonly IEmailService _emailService;
        private readonly ITokenService _tokenService;
        //private readonly IOptions<DataProtectionTokenProviderOptions> _tokenProviderOptions;
        public AuthService(UserManager<ApplicationUser> userManager,
            RoleManager<IdentityRole> roleManager,
            IEmailService emailService,
            ITokenService tokenService)
        {
            _userManager = userManager;
            _roleManager = roleManager;
            _emailService = emailService;
            _tokenService = tokenService;
        }

        public async Task<AuthModel> RegisterAsync(RegisterUser registerUser)
        {

            //check if user exists
            if (await _userManager.FindByEmailAsync(registerUser.Email) is not null)
                return new AuthModel { Message = "This Email is already used!" };
            if (await _userManager.FindByNameAsync(registerUser.UserName) is not null)
                return new AuthModel { Message = "This UserName is already used!" };
            // Check if the role exists
            //if (!await _roleManager.RoleExistsAsync(registerUser.Role))
            //    return new AuthModel { Message = "Role does not exist." };
            // Create the new user
            var user = new ApplicationUser
            {
                FirstName = registerUser.FirstName,
                LastName = registerUser.LastName,
                UserName = registerUser.UserName,
                Email = registerUser.Email
            };
            var result = await _userManager.CreateAsync(user, registerUser.Password);
            if (!result.Succeeded)
            {
                var errors = string.Empty;
                foreach (var item in result.Errors)
                {
                    errors += $"{item.Description}{Environment.NewLine}";
                }
                return new AuthModel { Message = errors };
            }
            // Assign the user to the specified role
            await _userManager.AddToRoleAsync(user, "User");

            //var roles = await _userManager.GetRolesAsync(user);

            //generating the token to verify the user's email
            var token = await _userManager.GenerateEmailConfirmationTokenAsync(user);

            // Dynamically get the expiration time from the options
            //var expirationTime = _tokenProviderOptions.Value.TokenLifespan.TotalMinutes;

            await _emailService.SendEmailAsync(user.Email, "Email Verification Code.",
                $"Hello {user.UserName}, \n Use this new token to verify your Email: {token}\n This code is Valid only for 5 Minutes.");

            return new AuthModel
            {
                Email = user.Email,
                //ExpiresAt = jwtSecurityToken.ValidTo,
                IsAuthenticated = true,
                //Roles = new List<string> { registerUser.Role },
                //Token = new JwtSecurityTokenHandler().WriteToken(jwtSecurityToken),
                Username = user.UserName,
                Message = "A verification code has been sent to your Email.\n Verify Your Email to be able to login :) "
            };

        }


        public async Task<AuthModel> LoginAsync(LoginModel loginModel)
        {
            var authModel = new AuthModel();
            var user = await _userManager.FindByEmailAsync(loginModel.Email); //check if the user exists
            if (user == null || !await _userManager.CheckPasswordAsync(user, loginModel.Password))
            {
                authModel.IsAuthenticated = false;
                authModel.Message = "Email or Password is incorrect!";
                return authModel;
            }
            if (!user.EmailConfirmed)
                return new AuthModel { Message = "Please Confirm Your Email First." };
            var jwtSecurityToken = await _tokenService.CreateJwtTokenAsync(user);
            authModel.IsAuthenticated = true;
            authModel.Email = user.Email;
            authModel.ExpiresAt = jwtSecurityToken.ValidTo;
            authModel.Roles = (await _userManager.GetRolesAsync(user)).ToList();
            authModel.Token = new JwtSecurityTokenHandler().WriteToken(jwtSecurityToken);
            authModel.Username = user.UserName;
            authModel.IsConfirmed = true;

            //checj if the user already has an active refresh token
            if (user.RefreshTokens.Any(t => t.IsActive))
            {
                var activeToken = user.RefreshTokens.FirstOrDefault(t => t.IsActive);
                authModel.RefreshToken = activeToken.Token;
                authModel.RefreshTokenExpiresOn = activeToken.ExpiresOn;
            }
            else
            {
                // Generate a new refresh token and add it to the user's tokens
                var refreshToken = await _tokenService.GenerateRefreshToken();
                user.RefreshTokens.Add(refreshToken);
                await _userManager.UpdateAsync(user);

                // Send the refresh token along with the JWT token
                authModel.RefreshToken = refreshToken.Token;
                authModel.RefreshTokenExpiresOn = refreshToken.ExpiresOn;
            }

            return authModel;
        }
        


        public async Task<string> AddRoleAsync(string role, string userName)
        {
            var user = await _userManager.FindByNameAsync(userName);
            if (user == null)
                return ("Invalid UserName!");
            if (!await _roleManager.RoleExistsAsync(role))
                return ("Invalid Role!");
            if (await _userManager.IsInRoleAsync(user, role))
                return ("User Is already assigned to this role!");
            var result = await _userManager.AddToRoleAsync(user, role);
            return $"User {userName} has been assignd to Role {role} Successfully :)";
        }

        public async Task<AuthModel> ResetPasswordAsync(string email, string token, string newPassword)
        {
            if (string.IsNullOrEmpty(email) || string.IsNullOrEmpty(newPassword))
                return new AuthModel { Message = "Email and Password are required!" };
            var user = await _userManager.FindByEmailAsync(email);
            if (user == null)
                return new AuthModel { Message = "Email is not correct!" };
            var result = await _userManager.ResetPasswordAsync(user, token, newPassword);
            if (!result.Succeeded)
                return new AuthModel { Message = "Token is not valid!" };
            return new AuthModel { Message = "Your password has ben reseted successfully." };
        }

        public async Task<AuthModel> ChangePasswordAsync(string email, string currentPassword, string newPassword)
        {
            if (string.IsNullOrEmpty(email) || string.IsNullOrEmpty(newPassword))
                return new AuthModel { Message = "Email and Password are required!" };
            var user = await _userManager.FindByEmailAsync(email);
            if (user == null)
                return new AuthModel { Message = "Email is not correct!" };
            var result = await _userManager.ChangePasswordAsync(user, currentPassword, newPassword);
            if (!result.Succeeded)
                return new AuthModel { Message = "Something went wronge!" };
            return new AuthModel { Message = "Your password has ben reseted successfully." };
        }

        public async Task<List<UserDto>> GetUSersAsync()
        {
            var users = await _userManager.Users.ToListAsync();
            var userDto = new List<UserDto>();
            foreach (var user in users)
            {
                var roles = await _userManager.GetRolesAsync(user);
                userDto.Add(new UserDto
                {
                    FirstName = user.FirstName,
                    LastName = user.LastName,
                    UserName = user.UserName,
                    Email = user.Email,
                    Roles = roles.ToList(),
                });
            }
            return userDto;
        }

        public async Task<AuthModel> DeleteUserAsync(string UserName)
        {
            var user = await _userManager.FindByNameAsync(UserName);
            if (user is null)
                return new AuthModel { Message = $"User with UserName: {UserName} isn't found!" };
            var result = await _userManager.DeleteAsync(user);
            if (!result.Succeeded)
                return new AuthModel { Message = $"An Error Occured while Deleting the user{UserName}" };
            return new AuthModel { Message = $"User with UserName: '{UserName}' has been Deleted successfully" };
        }
        //public Task LogoutAsync()
        //{
        //    throw new NotImplementedException();
        //}
    }
}
