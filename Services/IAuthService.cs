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
        Task<string> AddRoleAsync(AddRoleModel roleModel);
        Task<AuthModel> ResetPasswordAsync(ResetPasswordModel resetPasswordModel);
        Task<AuthModel> ChangePasswordAsync(ChangePasswordModel changePasswordModel);
        Task<List<UserDto>> GetUSersAsync();
        Task<AuthModel> DeleteUserAsync(string userName);
        Task<bool> LogoutAsync(string refreshToken);

    }
}
