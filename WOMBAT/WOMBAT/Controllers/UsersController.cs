using WOMBAT.Interfaces;
using WOMBAT.Models;
using WOMBAT.Tools;
using Microsoft.AspNetCore.Mvc;
using System.Net;

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
                return Ok(token);
            }
            return BadRequest("No auth header");


        }

        [HttpPost("Register")]
      
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

        public async Task<IActionResult> LogOut(User user)
        {
            var userResult = await _userRepo.GetUser(user.Email);

            if (userResult == null) return BadRequest("User not found");

            await _userRepo.ClearTokens(userResult.Id);

            return Ok("User logged out successfully");
        }

        [HttpGet("ConfirmEmail")]
        
        public async Task<IActionResult> ConfirmEmail(string id, string token)
        {
            var confirmationResult = await _userRepo.ConfirmEmail(id, token);
            if(!confirmationResult) return StatusCode(500, "Email confirmation failed");
            return Ok("Email confirmed successfuly");
        }


        [HttpGet("ValidateToken")]
        public async Task<IActionResult> ValidateToken()
        {

            string authHeader = this.HttpContext.Request.Headers["Authorization"];

            if (authHeader == null || !authHeader.StartsWith("Bearer")) return BadRequest("No auth header");

            var isValid = await _userRepo.ValidateJWT(authHeader);
            if(!isValid) return Unauthorized("Token invalid");
            return Ok("Token valid");

        }



    }
}
