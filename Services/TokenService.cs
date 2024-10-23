using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using UserAuthenticationApp.Models;

namespace UserAuthentication.Services
{
    public class TokenService : ITokenService
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly JWT _jwt;
        private readonly ILogger<TokenService> _logger;
        public TokenService(UserManager<ApplicationUser> userManager, IOptions<JWT> jwt, ILogger<TokenService> logger)
        {
            _userManager = userManager;
            _jwt = jwt.Value;
            _logger = logger;
        }
        public async Task<JwtSecurityToken> CreateJwtTokenAsync(ApplicationUser user)
        {
            var userClaim = await _userManager.GetClaimsAsync(user);
            var roles = await _userManager.GetRolesAsync(user);
            var roleClaims = new List<Claim>();
            foreach (var role in roles)
                roleClaims.Add(new Claim("roles", role));

            var claims = new Claim[] {
                new Claim(JwtRegisteredClaimNames.Sub, user.UserName),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                new Claim(JwtRegisteredClaimNames.Email, user.Email),
            }.Union(userClaim).Union(roleClaims);

            var signingCredentials = new SigningCredentials(new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_jwt.SigningKey)),
                SecurityAlgorithms.HmacSha256);
            var jwtSecurityToken = new JwtSecurityToken(
                issuer: _jwt.Issuer,
                audience: _jwt.Audience,
                claims: claims,
                expires: DateTime.UtcNow.AddMinutes(_jwt.Lifetime),
                signingCredentials: signingCredentials);

            return jwtSecurityToken;
        }

        public async Task<AuthModel> RefreshTokenAsync(string token)
        {
            var authModel = new AuthModel();
            var user = await _userManager.Users.SingleOrDefaultAsync(u => u.RefreshTokens.Any(t => t.Token == token));
            if (user == null)
            {
                authModel.IsAuthenticated = false;
                authModel.Message = "Invalid Token!";
                return authModel;
            }
            var refreshToken = user.RefreshTokens.Single(t => t.Token == token);
            if (!refreshToken.IsActive)
            {
                authModel.IsAuthenticated = false;
                authModel.Message = "Inactive Token!";
                return authModel;
            }
            // Revoke current refresh token
            refreshToken.RevokedOn = DateTime.UtcNow;
            var newRefreshToken = await GenerateRefreshToken();
            user.RefreshTokens.Add(newRefreshToken);
            await _userManager.UpdateAsync(user);

            // Save changes to prevent concurrency issues
            //    var updateResult = await _userManager.UpdateAsync(user);
            //    if (!updateResult.Succeeded)
            //    {
            //        authModel.IsAuthenticated = false;
            //        authModel.Message = "Failed to update user tokens!";
            //        return authModel;
            //    }

            var jwtToken = await CreateJwtTokenAsync(user);
            authModel.IsAuthenticated = true;
            authModel.Token = new JwtSecurityTokenHandler().WriteToken(jwtToken);
            authModel.Email = user.Email;
            authModel.Username = user.UserName;
            authModel.Roles = (await _userManager.GetRolesAsync(user)).ToList();
            authModel.RefreshToken = newRefreshToken.Token;
            authModel.RefreshTokenExpiresOn = newRefreshToken.ExpiresOn.ToLocalTime();
            return authModel;
        }
        
        public async Task<bool> RevokeTokenAsync(string token)
        {
            // Find user by refresh token
            var user = await _userManager.Users.SingleOrDefaultAsync(u => u.RefreshTokens.Any(t => t.Token == token));
            // Return false if user not found
            if (user == null)
            {
                _logger.LogInformation("Token revocation failed: user not found.");
                return false;
            }
            // Get the refresh token
            var refreshToken = user.RefreshTokens.Single(t => t.Token == token);
            // Return false if token is inactive (already revoked or expired)
            if (!refreshToken.IsActive)
            {
                _logger.LogInformation($"Token revocation failed: token already inactive for user {user.Email}");
                return false;
            }
            // Revoke the refresh token
            refreshToken.RevokedOn = DateTime.UtcNow.ToLocalTime();

            // Update user with revoked token
            var result = await _userManager.UpdateAsync(user);
            if (result.Succeeded)
            {
                _logger.LogInformation($"Token revoked successfully for user {user.Email} at {DateTime.UtcNow}");
                return true;
            }
            // Log and return false if update fails
            _logger.LogError($"Token revocation failed for user {user.Email} due to update failure.");
            return false;
        }


        public async Task<RefreshToken> GenerateRefreshToken()
        {
            var randomNumber = new byte[32];
            using var generator = new RNGCryptoServiceProvider();
            generator.GetBytes(randomNumber);
            return new RefreshToken
            {
                createdOn = DateTime.UtcNow,
                ExpiresOn = DateTime.Now.AddDays(1),
                Token = Convert.ToBase64String(randomNumber)
            };
        }

        
    }
}
