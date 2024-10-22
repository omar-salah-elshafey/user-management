using System.ComponentModel.DataAnnotations;

namespace UserAuthentication.Models
{
    public class RegisterUser
    {
        [Required, MaxLength(50)]
        public string FirstName { get; set; }
        [Required, MaxLength(50)]
        public string LastName { get; set; }
        [Required, MaxLength(50)]
        public string UserName { get; set; }
        [Required, MaxLength(50)]
        public string Email { get; set; }
        [Required, MaxLength(50)]
        public string Password { get; set; }
        //[Required, MaxLength(50)]
        //public string Role { get; set; }
    }
}
