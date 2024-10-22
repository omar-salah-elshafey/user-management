using System.ComponentModel.DataAnnotations;
using System.Text.Json.Serialization;

namespace UserAuthenticationApp.Models
{
    public class AuthModel
    {
        
        public string Message { get; set; }

        public bool IsAuthenticated { get; set; }
        public bool IsConfirmed { get; set; }
        public bool ISPasswordResetRequestVerified { get; set; }
        public string Username { get; set; }
        
        public string Email { get; set; }
        
        public List<string>? Roles { get; set; }

        public string Token { get; set; }

        public DateTime ExpiresAt { get; set; }
        //[JsonIgnore]
        //public string RefreshToken { get; set; }

        //public DateTime RefreshTokenExpiresOn { get; set; }
    }
}
