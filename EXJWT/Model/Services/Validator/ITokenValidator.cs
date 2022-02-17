using EXJWT.Model.Services.Repository;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;

namespace EXJWT.Model.Services.Validator
{
  public  interface ITokenValidator
    {
        Task Execute(TokenValidatedContext context);
    }

    public class TokenValidator : ITokenValidator
    {
        private readonly UserRepository userRepository;
        private readonly UserTokenRepository userTokenRepository;
        public TokenValidator(UserRepository user , UserTokenRepository userToken )
        {
            userRepository = user;
            userTokenRepository = userToken;

        }
        public async Task Execute(TokenValidatedContext context)
        {
            var claimsidentity = context.Principal.Identity as ClaimsIdentity;
            if (claimsidentity == null)
            {
                context.Fail("claim not fund...");
                return;
            }
            var user = claimsidentity.FindFirst("Id").Value;
            var UserId = int.TryParse(user, out int userId);
            var userFind = userRepository.Get(userId);
            if (!userFind.IsActive)
            {
                context.Fail("user not active ...");
                return;
            }

             if(!(context.SecurityToken is JwtSecurityToken Token) || !(userTokenRepository.CheckExistToken(Token.RawData)))
            {
                context.Fail("token not exsist ....");
                return;
            }
        }
    }

}
