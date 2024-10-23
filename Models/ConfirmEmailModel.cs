using System.ComponentModel.DataAnnotations;

namespace UserAuthentication.Models
{
    public class ConfirmEmailModel
    {
        [Required]
        public string Email { get; set; }
        [Required]
        public string Token { get; set; }

    }
}
