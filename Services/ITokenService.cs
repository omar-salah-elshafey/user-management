using System.IdentityModel.Tokens.Jwt;
using UserAuthenticationApp.Models;

namespace UserAuthentication.Services
{
    public interface ITokenService
    {
        Task<JwtSecurityToken> CreateJwtTokenAsync(ApplicationUser user);
        Task<AuthModel> RefreshTokenAsync(string token);
        Task<bool> RevokeTokenAsync(string token);
        Task<RefreshToken> GenerateRefreshToken();
    }
}
