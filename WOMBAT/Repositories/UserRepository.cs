using AutoMapper;
using WOMBAT.Data;
using WOMBAT.Interfaces;
using WOMBAT.Models;
using WOMBAT.Tools;
using Microsoft.AspNetCore.Identity;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using System.Data;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using System.Net.Mail;
using Microsoft.EntityFrameworkCore.Metadata.Internal;

namespace WOMBAT.Repositories
{
    public class UserRepository : IUserRepository
    {
        private readonly ApplicationDbContext _db;
        private readonly UserManager<User> _userManager;
        private readonly IMapper _mapper;
        private IConfiguration _config;
        private readonly RoleManager<IdentityRole> _roleManager;
        public UserRepository(IConfiguration config, IMapper mapper, ApplicationDbContext db, UserManager<User> userManager, RoleManager<IdentityRole> roleManager) {
            _db = db;
            _userManager = userManager;
            _mapper = mapper;
            _config = config;
            _roleManager = roleManager;
        }

        public async Task<User> GetUser(string mail)
        {

            User user = await _userManager.FindByEmailAsync(mail);
            return user;
           
        }

        public async Task<bool> PasswordCheck(User user, string password)
        {
            var check = await _userManager.CheckPasswordAsync(user, password + user.Salt);
            if(!check) return false;
            return true;
        }

        public async Task<bool> ClearTokens(string UserId)
        {
            var tokens = _db.UserTokens.Where(t => t.UserId == UserId);
            if (tokens.Count() == 0) return false;
           
            foreach(var token in tokens)
            {
                    _db.UserTokens.Remove(token);
            }
           _db.SaveChanges();
          

            return true;

        }

        public async Task<List<string>> GetRoles(User user)
        {
            var roleList = await _userManager.GetRolesAsync(user);

            if (roleList.Count <= 0) return new List<string> ();

            return roleList.ToList() ;
        }

        public async Task<string> GenerateToken(User user, List<string> roles)
        {
            await ClearTokens(user.Id);

            IEnumerable<Claim> claims = Enumerable.Empty<Claim> ();

            claims.Append(new Claim("Email", user.Email));
            claims.Append(new Claim(ClaimTypes.NameIdentifier, user.UserName));

            
            foreach(var role in roles) {
                claims.Append(new Claim(ClaimTypes.Role, role));
            }
     
            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_config.GetValue<string>("JWT:Key")));
            JwtSecurityToken JWT = new JwtSecurityToken(issuer: _config.GetValue<string>("JWT:Issuer"), audience: _config.GetValue<string>("JWT:Audience"), claims: claims, expires: DateTime.Now.AddDays(1), signingCredentials: new SigningCredentials(key, SecurityAlgorithms.HmacSha256));



            string JWTstring = new JwtSecurityTokenHandler().WriteToken(JWT);
            _db.UserTokens.Add(new IdentityUserToken<string> { LoginProvider = "", Name = "", UserId = user.Id, Value = JWTstring });
            _db.SaveChanges();

            return JWTstring;
        }

        public async Task<User> CreateUser(ViewUser vu)
        {
            var user = _mapper.Map<User>(vu);

            string salt = EncodingTools.Salt();

            user.Salt = salt;

            vu.Pass += salt;

            var result = await _userManager.CreateAsync(user, vu.Pass);

            if(!result.Succeeded)
            {

                return null;
            }

            return user;
        }

        public async Task<bool> AssignRole(User user, string role)
        {
            var roleResult = await _userManager.AddToRoleAsync(user, role);

            if (!roleResult.Succeeded) return false;
            return true;
        }

        public async Task<bool> DeleteUser(User user)
        {
            var result = await _userManager.DeleteAsync(user);

            if(!result.Succeeded) return false;
            return true;
        }

        public async Task<bool> CheckUsernameTaken(string name)
        {
            var user = await _userManager.FindByNameAsync(name);
            if (user == null) return false;
            return true;
        }
        public async Task<bool> ChangePassword(string authHeader, string token)
        {
            var decodedToken = EncodingTools.DecodeToken(token);

            var userData = EncodingTools.DecodeLoginHeader(authHeader);

            var user = await _userManager.FindByIdAsync(userData.Mail);
            var passResult = await _userManager.ResetPasswordAsync(user, decodedToken, userData.Pass + user.Salt);
            if(!passResult.Succeeded) return false;
            return true;

        }

        public async Task<bool> ChangeMail(string uid, string newMail, string token)
        {
            var user = await _userManager.FindByIdAsync(uid);

            var decodedToken = EncodingTools.DecodeToken(token);

            var mailResult = await _userManager.ChangeEmailAsync(user, newMail, decodedToken);
            if(!mailResult.Succeeded) return false;
            return true;

        }

        public async Task<string> GenerateEmailChangeToken(User user, string newMail)
        {
            var token = await _userManager.GenerateChangeEmailTokenAsync(user, newMail);
            return token;
        }

        

        public async Task<string> GenerateEmailConfirmationToken(User user)
        {
            var token = await _userManager.GenerateEmailConfirmationTokenAsync(user);
            if (token == null || string.IsNullOrWhiteSpace(token)) return null;
            return token;
        }

        public async Task<bool> ConfirmEmail(string uid, string token)
        {
            var user = await _userManager.FindByIdAsync(uid);

            var decodedToken = EncodingTools.DecodeToken(token);

            var confirmResult = await _userManager.ConfirmEmailAsync(user, decodedToken);

            if(!confirmResult.Succeeded) return false;
            return true;
        }

        public async Task<bool> EmailConfirmedCheck(User user)
        {
            return await _userManager.IsEmailConfirmedAsync(user);
        }

        public async Task<bool> ValidateJWT(string header)
        {
            var token = EncodingTools.CleanHeaderJWT(header);

            var handler = new JwtSecurityTokenHandler();

            if (!handler.CanReadToken(token)) return false;

            try
            {
                handler.ValidateToken(token, new TokenValidationParameters
                {
                    ValidateIssuerSigningKey = true,
                    IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_config.GetValue<string>("JWT:Key"))),
                    ValidateIssuer = true,
                    ValidateAudience = true,
                    ValidAudience = _config.GetValue<string>("JWT:Audience"),
                    ValidIssuer = _config.GetValue<string>("JWT:Issuer"),
                    ClockSkew = TimeSpan.Zero
                }, out SecurityToken validatedToken) ;

                
            }
            catch(Exception ex) 
            {

                return false;
            }


            var dbToken = _db.UserTokens.Where(t => t.Value == token);
            if(dbToken.Count() == 0) return false;

            return true;
       

        }

        public async Task<bool> ClearToken(string header)
        {

            var token = EncodingTools.CleanHeaderJWT(header);
            var dbToken = _db.UserTokens.Where(t => t.Value == token).FirstOrDefault();
            if (dbToken == null) return false;
            _db.UserTokens.Remove(dbToken);
            _db.SaveChanges();
            return true;
        }



        // MAIL




        public async Task<bool> SendChangeEmailConfirmation(string mail, string newMail)
        {

            var user = await _userManager.FindByEmailAsync(mail);

            if (user == null) return false;

            var token = await GenerateEmailChangeToken(user, newMail);
            var encodedToken = EncodingTools.EncodeToken(token);

            string Url = _config.GetValue<string>("MailService:ChangeMailUrl");
            string Args = $"/?id={user.Id}&newMail={newMail}&token={encodedToken}";
            string Link = $"To confirm email change, please click <a href='{Url + Args}'>Here</a>";

            await SendMail(newMail, "Email change", Link);

            return true;
        }

    

        public async Task<bool> SendMail(string to, string subject, string message)
        {
            var senderMail = _config.GetValue<string>("MailService:Mail");
            var senderPass = _config.GetValue<string>("MailService:Pass");
            var server = _config.GetValue<string>("MailService:SmtpServer");
            var port = _config.GetValue<int>("MailService:Port");

            var address = new MailAddress(senderMail);
            MailMessage mail = new MailMessage();
            mail.From = address;

            mail.Subject = subject;
            mail.To.Add(new MailAddress(to));

            SmtpClient smtp = new SmtpClient(server, port);
            smtp.EnableSsl = true;
            smtp.UseDefaultCredentials = false;
            smtp.Credentials = new System.Net.NetworkCredential(senderMail, senderPass);
            mail.IsBodyHtml= true;

            mail.Body = message;
            try
            {
                smtp.Send(mail);
            }
            catch(Exception ex)
            {
                smtp.Dispose();
                return false;
            }

            

            smtp.Dispose();

            return true;

        }

        public async Task<bool> SendConfirmationMail(User user)
        {
            var token = await GenerateEmailConfirmationToken(user);

            if (token == null) return false;

            var encodedToken = EncodingTools.EncodeToken(token);

            string Url = _config.GetValue<string>("MailService:ConfirmationUrl");
            string Args = $"/?id={user.Id}&token={encodedToken}";
            string Link = $"To confirm your email, please click <a href='{Url + Args}'>Here</a>";

            var sendResult = await SendMail(user.Email, "Email confirmation", Link);

            return sendResult;
        }



        public async Task<bool> SendPasswordResetConfirmation(string mail)
        {
            var user = await _userManager.FindByEmailAsync(mail);

            if (user == null) return false;

            var token = await GeneratePasswordResetToken(user);
            if (token == null) return false;

            var encodedToken = EncodingTools.EncodeToken(token);

            string Url = _config.GetValue<string>("MailService:PasswordResetUrl");
            string Args = $"?uid={user.Id}&token={encodedToken}";
            string Link = $"To reset your password, please click <a href='{Url + Args}'>Here</a>";

            var sendResult = await SendMail(user.Email, "Reset your password", Link);

            return sendResult;

        }

        public async Task<string> GeneratePasswordResetToken(User user)
        {
            var token = await _userManager.GeneratePasswordResetTokenAsync(user);
            if (token == null || string.IsNullOrWhiteSpace(token)) return null;
            return token;
        }
    }
}
