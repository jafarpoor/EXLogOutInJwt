using EXJWT.Helper;
using EXJWT.Model.Entites;
using EXJWT.Model.Services.Dto;
using EXJWT.Model.Services.Repository;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;

namespace EXJWT.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AccountentController : ControllerBase
    {
        private readonly UserTokenRepository userTokenRepository;
        private readonly UserRepository userRepository;
        private readonly IConfiguration configuration;
        public AccountentController(UserTokenRepository userToken , UserRepository user , IConfiguration confg )
        {
            userTokenRepository = userToken;
            userRepository = user;
            configuration = confg;
        }


        [HttpPost]
      //  [Authorize]
        public IActionResult post(string PhoneNumber , string smsCode)
        {
            var LoginResult = userRepository.Login(PhoneNumber, smsCode);
            if (!LoginResult.IsSuccess)
            {
                return Unauthorized(LoginResult.Message);
            }
            var token = CreatToken(LoginResult.MyUser);
            return Ok(token);

        }

        [HttpGet]
        [Route("LogOut")]
        [Authorize]
        public IActionResult LogOut()
        {
            var user = User.Claims.First(p => p.Type == "Id").Value;
            userRepository.LogOut(int.Parse(user));
            return Ok();

        }

        [Route("GetSmsCode")]
        [HttpGet]
        public IActionResult GetSmsCode(string PhoneNumber)
        {
            var code = userRepository.GetSmsCode(PhoneNumber);
            //اسال پیامک
            return Ok();

        }

        [HttpPost]
        [Route("RefreshTokens")]
        public IActionResult RefreshTokens(string RefreshToken)
        {
            var refreshtoken = userTokenRepository.FindRefreshToken(RefreshToken);
            if (refreshtoken ==null)
            {
                return Unauthorized();
            }
            if (refreshtoken.RefrshTokenExp <DateTime.Now)
            {
                return Unauthorized();

            }
            userTokenRepository.DeletToken(RefreshToken);
            var token = CreatToken(refreshtoken.User);
          
            return Ok(token);

        }

        private LoginResultDto CreatToken(UserDto userDto)
        {
            SecurityHelper securityHelper = new SecurityHelper();
                var claims = new List<Claim>
                {
                    new Claim ("Id", userDto.Id.ToString()),
                    new Claim ("Name",  userDto?.Name??""),
                };
                string key = configuration["JWtConfig:Key"];
                var secretKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(key));
                var credentials = new SigningCredentials(secretKey, SecurityAlgorithms.HmacSha256);
                var tokenexp = DateTime.Now.AddMinutes(int.Parse(configuration["JWtConfig:expires"]));
                var token = new JwtSecurityToken(
                    issuer: configuration["JWtConfig:issuer"],
                    audience: configuration["JWtConfig:audience"],
                    expires: tokenexp,
                    notBefore: DateTime.Now,
                    claims: claims,
                    signingCredentials: credentials
                    );


                var MyJwt = new JwtSecurityTokenHandler().WriteToken(token);
                var RefrshToken = Guid.NewGuid();
                userTokenRepository.SaveToken(new UserTokenDto()
                {
                    MobilModel = "Iphone pro MAx",
                    ExpTime = tokenexp,
                    HashToken = securityHelper.Getsha256Hash(MyJwt),
                    UserId = userDto.Id,
                    RefrshToken = securityHelper.Getsha256Hash(RefrshToken.ToString()),
                    RefrshTokenExp =DateTime.Now.AddDays(30),
                    User =userDto
                });


            return new LoginResultDto
            {
                RefreshToken = RefrshToken.ToString(),
                Token = MyJwt
            };
        }
    }
}
