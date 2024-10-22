using System.ComponentModel.DataAnnotations;

namespace UserAuthentication.Models
{
    public class AddRoleModel
    {
        [Required]
        public string UserName { get; set; }
        [Required]
        public string Role { get; set; }
    }
}
