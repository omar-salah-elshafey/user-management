using System.IdentityModel.Tokens.Jwt;
using UserAuthenticationApp.Models;

namespace UserAuthentication.Services
{
    public interface ITokenService
    {
        Task<JwtSecurityToken> CreateJwtTokenAsync(ApplicationUser user);
    }
}
