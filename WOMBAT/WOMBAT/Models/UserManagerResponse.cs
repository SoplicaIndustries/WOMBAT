namespace WOMBAT.Models
{
    public class UserManagerResponse
    {
        public string Message { get; set; }

        public bool Status { get; set; }

        public IEnumerable<string>? Errors { get; set; }

        public User user  { get; set; }
    }
}
