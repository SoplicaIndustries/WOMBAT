using System.ComponentModel.DataAnnotations;

namespace WOMBAT.Models
{
    public class ViewUser
    {
        [Required]
        public string Pass { get; set; }
        [Required]
        public string Username { get; set; }
        [Required]
        public string Mail { get; set; }
        [Required]
        public string Role { get; set; }
    }
}
