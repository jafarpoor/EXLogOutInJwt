using EXJWT.Helper;
using EXJWT.Model.Context;
using EXJWT.Model.Entites;
using Microsoft.EntityFrameworkCore;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace EXJWT.Model.Services.Repository
{
    public class UserTokenRepository
    {
        private readonly DataBaseContext MyContext;
        public UserTokenRepository(DataBaseContext dataBaseContext)
        {
            MyContext = dataBaseContext;
        }

        public void SaveToken(UserTokenDto userTokenDto)
        {
            UserToken MyUserToken = new UserToken{
              //   Id = userTokenDto.Id,
                 ExpTime = userTokenDto.ExpTime ,
                 HashToken = userTokenDto.HashToken,
                 MobilModel=userTokenDto.HashToken,
                 UserId = userTokenDto.UserId   ,
                 RefrshToken =userTokenDto.RefrshToken,
                 RefrshTokenExp =userTokenDto.RefrshTokenExp
            };
            MyContext.UserTokens.Add(MyUserToken);
            MyContext.SaveChanges();
                  
        }

        public UserTokenDto FindRefreshToken(string RefreshToken)
        {
            SecurityHelper MySecurityHelper = new SecurityHelper();
            var RefreshToknHash = MySecurityHelper.Getsha256Hash(RefreshToken);
            var MyrefreshToken = MyContext.UserTokens.Include(p => p.User).FirstOrDefault(p => p.RefrshToken == RefreshToknHash);

            return new UserTokenDto
            {
                Id = MyrefreshToken.Id,
                ExpTime = MyrefreshToken.ExpTime,
                RefrshTokenExp = MyrefreshToken.RefrshTokenExp,
                RefrshToken = MyrefreshToken.RefrshToken,
                HashToken = MyrefreshToken.HashToken,
                MobilModel = MyrefreshToken.MobilModel,
                UserId = MyrefreshToken.UserId,
                User =new UserDto { 
                    IsActive=MyrefreshToken.User.IsActive,
                    Name=MyrefreshToken.User.Name,
                    PhoneNumber=MyrefreshToken.User.PhoneNumber ,
                    Id= MyrefreshToken.User.Id,
                    userTokens = null
                }
                
            };

        }

        public void DeletToken(string refeshtoken)
        {
                SecurityHelper MySecurityHelper = new SecurityHelper();
                var RefreshToknHash = MySecurityHelper.Getsha256Hash(refeshtoken);
                var MyrefreshToken = MyContext.UserTokens.Include(p => p.User).FirstOrDefault(p => p.RefrshToken == RefreshToknHash);
                if (MyrefreshToken != null)
            {
                MyContext.UserTokens.Remove(MyrefreshToken);
                MyContext.SaveChanges();
            }
        }

        public bool CheckExistToken(string Token)
        {
            SecurityHelper MySecurityHelper = new SecurityHelper();
            var RefreshToknHash = MySecurityHelper.Getsha256Hash(Token);
            var TokenResult = MyContext.UserTokens.Where(p => p.HashToken == RefreshToknHash).FirstOrDefault();
            return TokenResult == null ? false : true;
        }

    }
}
