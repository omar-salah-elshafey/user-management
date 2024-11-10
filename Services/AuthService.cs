﻿using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using Microsoft.VisualStudio.Web.CodeGenerators.Mvc.Templates.BlazorIdentity.Pages.Manage;
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
        private readonly IEmailService _emailService;
        private readonly ITokenService _tokenService;
        private readonly ILogger<AuthService> _logger;
        private readonly IOptions<DataProtectionTokenProviderOptions> _tokenProviderOptions;
        public AuthService(UserManager<ApplicationUser> userManager,
            RoleManager<IdentityRole> roleManager,
            IEmailService emailService,
            ITokenService tokenService,
            ILogger<AuthService> logger,
            IOptions<DataProtectionTokenProviderOptions> tokenProviderOptions)
        {
            _userManager = userManager;
            _roleManager = roleManager;
            _emailService = emailService;
            _tokenService = tokenService;
            _logger = logger;
            _tokenProviderOptions = tokenProviderOptions;
        }

        public async Task<AuthModel> RegisterAsync(RegisterUser registerUser, string role)
        {

            //check if user exists
            if (await _userManager.FindByEmailAsync(registerUser.Email) is not null)
                return new AuthModel { Message = "This Email is already used!" };
            if (await _userManager.FindByNameAsync(registerUser.UserName) is not null)
                return new AuthModel { Message = "This UserName is already used!" };
            
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
            await _userManager.AddToRoleAsync(user, role);

            //generating the token to verify the user's email
            var token = await _userManager.GenerateEmailConfirmationTokenAsync(user);

            // Dynamically get the expiration time from the options
            var expirationTime = _tokenProviderOptions.Value.TokenLifespan.TotalMinutes;

            await _emailService.SendEmailAsync(user.Email, "Email Verification Code.",
                $"Hello {user.UserName}, \n Use this new token to verify your Email: {token}\n This code is Valid only for {expirationTime} Minutes.");

            return new AuthModel
            {
                Email = user.Email,
                IsAuthenticated = true,
                Username = user.UserName,
                Message = $"A verification code has been sent to your Email.\n Verify Your Email to be able to login :) "
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
        


        public async Task<string> AddRoleAsync(AddRoleModel roleModel)
        {
            var user = await _userManager.FindByNameAsync(roleModel.UserName);
            if (user == null)
                return ("Invalid UserName!");
            if (!await _roleManager.RoleExistsAsync(roleModel.Role))
                return ("Invalid Role!");
            if (await _userManager.IsInRoleAsync(user, roleModel.Role))
                return ("User Is already assigned to this role!");
            var result = await _userManager.AddToRoleAsync(user, roleModel.Role);
            return $"User {roleModel.UserName} has been assignd to Role {roleModel.Role} Successfully :)";
        }

        public async Task<AuthModel> ResetPasswordAsync(ResetPasswordModel resetPasswordModel)
        {
            if (string.IsNullOrEmpty(resetPasswordModel.Email) || string.IsNullOrEmpty(resetPasswordModel.NewPassword))
                return new AuthModel { Message = "Email and Password are required!" };
            var user = await _userManager.FindByEmailAsync(resetPasswordModel.Email);
            if (user == null)
                return new AuthModel { Message = "Email is not correct!" };
            if (!resetPasswordModel.NewPassword.Equals(resetPasswordModel.ConfirmNewPassword))
            {
                return new AuthModel { Message = "Confirm the new Password!" };
            }
            var result = await _userManager.ResetPasswordAsync(user, resetPasswordModel.Token, resetPasswordModel.NewPassword);
            if (!result.Succeeded)
                return new AuthModel { Message = "Token is not valid!" };
            return new AuthModel { Message = "Your password has ben reseted successfully." };
        }

        public async Task<AuthModel> ChangePasswordAsync(ChangePasswordModel changePasswordModel)
        {
            if (string.IsNullOrEmpty(changePasswordModel.Email) || string.IsNullOrEmpty(changePasswordModel.CurrentPassword))
                return new AuthModel { Message = "Email and Password are required!" };
            var user = await _userManager.FindByEmailAsync(changePasswordModel.Email);
            if (user == null)
                return new AuthModel { Message = "Email is not correct!" };
            if(changePasswordModel.CurrentPassword.Equals(changePasswordModel.NewPassword))
                return new AuthModel { Message = "New and Old Password cannot be the same!" };
            if (!changePasswordModel.NewPassword.Equals(changePasswordModel.ConfirmNewPassword))
            {
                return new AuthModel { Message = "Confirm the new Password!" };
            }
            var result = await _userManager.ChangePasswordAsync(user, changePasswordModel.CurrentPassword, changePasswordModel.NewPassword);
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
        public async Task<bool> LogoutAsync(string refreshToken)
        {
            // Revoke the refresh token
            var result = await _tokenService.RevokeTokenAsync(refreshToken);

            if (!result)
            {
                _logger.LogInformation("Failed to revoke token during logout.");
                return false;
            }

            _logger.LogInformation("User logged out successfully.");
            return true;
        }

        public async Task<UpdateUserModel> UpdateUserAsync(UpdateUserModel updateUserModel)
        {
            if (string.IsNullOrEmpty(updateUserModel.UserName) 
                || string.IsNullOrEmpty(updateUserModel.FirstName) || string.IsNullOrEmpty(updateUserModel.LastName))
                return new UpdateUserModel { Message = "UserName, FirstName, and LastName are required!" };
            var user = await _userManager.FindByNameAsync(updateUserModel.UserName);
            if (user is null)
                return new UpdateUserModel { Message = $"User with UserName: {updateUserModel.UserName} isn't found!" };
            user.UserName = updateUserModel.UserName;
            user.FirstName = updateUserModel.FirstName;
            user.LastName = updateUserModel.LastName;
            await _userManager.UpdateAsync(user);
            return new UpdateUserModel
            {
                UserName = updateUserModel.UserName,
                FirstName = updateUserModel.FirstName,
                LastName = updateUserModel.LastName,
                Message = "User has been Updated successfully."
            };
        }
    }
}
