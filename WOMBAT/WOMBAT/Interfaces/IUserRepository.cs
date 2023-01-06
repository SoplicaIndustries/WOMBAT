using WOMBAT.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.IdentityModel.JsonWebTokens;

namespace WOMBAT.Interfaces
{
    public interface IUserRepository
    {
        Task<User> GetUser(string mail);

        Task<bool> PasswordCheck(User user, string password);

        Task<bool> EmailConfirmedCheck(User user);

        Task ClearTokens(string UserId);

        Task<List<string>> GetRoles(User user);

        Task<string> GenerateToken(User user, List<string> roles);

        Task<User> CreateUser(ViewUser vu);

        Task<bool> AssignRole (User user, string role); 

        Task<bool> DeleteUser (User user);

        Task<bool> CheckUsernameTaken(string name);

        Task<bool> ChangePassword(User user, string currentPass, string newPass);

        Task<string> GenerateEmailChangeToken(User user, string newMail);
        Task<bool> ChangeMail(string mail, string newMail, string token);

        Task<bool> SendConfirmationMail(User user);

        Task<string> GenerateEmailConfirmationToken(User user);

        Task<bool> ConfirmEmail(string uid, string token);




    }
}
