using WOMBAT.Interfaces;
using WOMBAT.Models;
using WOMBAT.Tools;
using Microsoft.AspNetCore.Mvc;
using System.Net;
using System.IO.Pipelines;
using Microsoft.AspNetCore.Mvc.Filters;
using WOMBAT.Filters;

namespace WOMBAT.Controllers
{

    [Route("api/[controller]")]
    [ApiController]
    public class UsersController : ControllerBase
    {

        private IUserRepository _userRepo { get; set; }
        public UsersController(IUserRepository UserRepo) { 
            _userRepo = UserRepo;
        }


        [HttpPost("Login")]
        [ServiceFilter(typeof(ActionFilters))]
        public async Task<IActionResult> Login() 
        {

            //User repo login function to login, function will return action result

            string authHeader = this.HttpContext.Request.Headers["Authorization"];

            if (authHeader != null && authHeader.StartsWith("Basic"))
            {
                
                var userData = EncodingTools.DecodeLoginHeader(authHeader);

                var user = await _userRepo.GetUser(userData.Mail);

                if (user == null) return NotFound("User not found");

                var passCheck = await _userRepo.PasswordCheck(user, userData.Pass);

                if (!passCheck) return Unauthorized("Wrong password");

                var isEmailConfirmed = await _userRepo.EmailConfirmedCheck(user);

                if (!isEmailConfirmed) return Unauthorized("Email needs to be confirmed");

                var RoleList = await _userRepo.GetRoles(user);

                if (RoleList.Count() == 0) return StatusCode(500, "No roles");
                var token = await _userRepo.GenerateToken(user, RoleList);
                return Ok(new { token, user.Id, user.UserName, user.Email });
            }
            return BadRequest("No auth header");


        }

        [HttpPost("Register")]
        [ServiceFilter(typeof(ActionFilters))]

        public async Task<IActionResult> Register(ViewUser vu)
        {

            if(!ModelState.IsValid) return BadRequest(ModelState);

            var usernameResult = await _userRepo.CheckUsernameTaken(vu.Username);

            if(usernameResult) return BadRequest("Username already taken");

            var userResult = await _userRepo.CreateUser(vu);

            if(userResult == null) return StatusCode(500);

            var roleResult = await _userRepo.AssignRole(userResult, vu.Role);

            if (roleResult == false)
            {
                await _userRepo.DeleteUser(userResult);
                return StatusCode(404, "Failed to add to role");
            }

            await _userRepo.SendConfirmationMail(userResult);

            return Ok("User created successfully");
        }

        

        [HttpPost("LogOut")]
        [ServiceFilter(typeof(ActionFilters))]

        public async Task<IActionResult> LogOut()
        {
            string authHeader = this.HttpContext.Request.Headers["Authorization"];

            if (authHeader == null || !authHeader.StartsWith("Bearer")) return BadRequest("No auth header");

            var result = await _userRepo.ClearToken(authHeader);

            if (!result) return BadRequest("Invalid token");

            return Ok("User logged out successfully");
        }

        [HttpPost("LogOutAllDevices")]
        [ServiceFilter(typeof(ActionFilters))]
        public async Task<IActionResult> LogOutAllDevices(string uid)
        {
            var result = await _userRepo.ClearTokens(uid);

            if (!result) return NotFound("Invalid user id or no tokens found");

            return Ok("User logged out successfully");
        }


        [HttpPost("ConfirmEmail")]
        [ServiceFilter(typeof(ActionFilters))]

        public async Task<IActionResult> ConfirmEmail(string id, string token)
        {
            var confirmationResult = await _userRepo.ConfirmEmail(id, token);
            if(!confirmationResult) return StatusCode(500, "Email confirmation failed");
            return Ok("Email confirmed successfuly");
        }


        [HttpPost("ValidateToken")]
        [ServiceFilter(typeof(ActionFilters))]
        public async Task<IActionResult> ValidateToken()
        {

            string authHeader = this.HttpContext.Request.Headers["Authorization"];

            if (authHeader == null || !authHeader.StartsWith("Bearer")) return BadRequest("No auth header");

            var isValid = await _userRepo.ValidateJWT(authHeader);
            if(!isValid) return Unauthorized("Token invalid");
            return Ok("Token valid");

        }



        [HttpPost("SendChangeEmailConfirmation")]
        [ServiceFilter(typeof(ActionFilters))]
        public async Task<IActionResult> SendChangeEmailConfirmation(string mail, string newMail)
        {

            var sendResult = await _userRepo.SendChangeEmailConfirmation(mail, newMail);
            if (!sendResult) return StatusCode(500, "Failed to send email");
            return Ok("Email sent");
        }


        [HttpPost("ChangeEmail")]
        [ServiceFilter(typeof(ActionFilters))]
        public async Task<IActionResult> ChangeEmail(string id, string newMail, string token)
        {
            var sendResult = await _userRepo.ChangeMail(id, newMail, token);
            if (!sendResult) return StatusCode(500, "Failed to change mail");
            return Ok("Email changed");
        }




        [HttpPost ("SendResetPasswordConfirmation")]
        [ServiceFilter(typeof(ActionFilters))]
        public async Task<IActionResult> SendResetPasswordConfirmation(string mail)
        {

            var sendResult = await _userRepo.SendPasswordResetConfirmation(mail);
            if (!sendResult) return StatusCode(500, "Failed to send email");
            return Ok("Email sent");
        }

        [HttpPost("ResetPassword")]
        [ServiceFilter(typeof(ActionFilters))]
        public async Task<IActionResult> ResetPassword(string token)
        {
            string authHeader = this.HttpContext.Request.Headers["Authorization"];

            if (authHeader == null || !authHeader.StartsWith("Basic")) return BadRequest("no auth header");

            var resetResult = await _userRepo.ChangePassword(authHeader, token);
            if (!resetResult) return StatusCode(500, "Failed to change password");
            return Ok("Password changed");
        }


    }
}
