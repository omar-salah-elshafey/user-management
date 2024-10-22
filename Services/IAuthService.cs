using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using UserAuthentication.Models;
using UserAuthenticationApp.Models;

namespace UserAuthentication.Services
{
    public interface IAuthService
    {
        Task<AuthModel> RegisterAsync(RegisterUser registerUser);
        Task<AuthModel> LoginAsync(LoginModel loginModel);
        Task<AuthModel> DeleteUserAsync(string userName);
        Task<string> AddRoleAsync(string role, string userName);
        Task<AuthModel> ResetPasswordAsync(string email, string token, string newPassword);

    }
}
