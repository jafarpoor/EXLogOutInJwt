using EXJWT.Model.Context;
using EXJWT.Model.Entites;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace EXJWT.Model.Services.Repository
{
    public partial class UserRepository
    {
        private readonly DataBaseContext MyContext;
        public UserRepository(DataBaseContext dataBaseContext)
        {
            MyContext = dataBaseContext;
        }

        public UserDto Get(int id)
        {
            var Result = MyContext.Users.FirstOrDefault(p=>p.Id == id);
            List<UserTokenDto> MyUserToken = new List<UserTokenDto>();
            foreach (var item in Result.userTokens)
            {
                MyUserToken.Add(new UserTokenDto
                {
                    Id = item.Id,
                    ExpTime = item.ExpTime,
                    HashToken = item.HashToken,
                    MobilModel = item.MobilModel,
                    UserId = item.UserId,
                    RefrshToken = item.RefrshToken,
                    RefrshTokenExp =item.RefrshTokenExp,
                    
                });
            }
            return new UserDto
            {
                Id = Result.Id,
                IsActive = Result.IsActive,
                Name = Result.Name,
                userTokens = MyUserToken,
                PhoneNumber=Result.PhoneNumber
            };
        }

        public bool ValidateUser(string UserName , string PassWord)
        {
            var uer = MyContext.Users.FirstOrDefault();
            return uer == null ? false : true;
        }

         public string GetSmsCode(string PhoneNumber)
        {
            Random random = new Random();
            string code = random.Next(1000, 9999).ToString();
            SmsCode sms = new SmsCode
            {
                Code = code,
                InsertTime = DateTime.Now,
                PhoneNumber = PhoneNumber,
                RequestCount = 0,
                UsedCode = false
            };
            MyContext.smsCodes.Add(sms);
            MyContext.SaveChanges();
            return code;
        }

        public LoginDto Login(string PhoneNumber , string Code)
        {
            var SmsCode = MyContext.smsCodes.Where(p => p.PhoneNumber.EndsWith(PhoneNumber) && p.Code == Code).FirstOrDefault();
            if (SmsCode == null)
            {
                return new LoginDto
                {
                    IsSuccess = false,
                    Message = " کد وارد شده صحیح نمی باشد",
                };
            }
            else
            {
                if (SmsCode.UsedCode)
                {
                    return new LoginDto
                    {
                        IsSuccess = false,
                        Message = " کد وارد شده صحیح نمی باشد",
                    };
                }

                SmsCode.RequestCount++;
                SmsCode.UsedCode = true;
                MyContext.SaveChanges();
                var user = FindUserWithPhonenumber(PhoneNumber);
                if (user != null)
                {
                    return new LoginDto
                    {
                        IsSuccess = true,
                       MyUser = new UserDto
                       {
                           IsActive= user.IsActive,
                           PhoneNumber = user.PhoneNumber,
                           Name=user.Name ,
                           Id = user.Id
                       }
                    };
                }
                else
                {
                    var Myusers = RegistrUser(PhoneNumber);
                    return new LoginDto
                    {
                        IsSuccess = true,
                        MyUser = new UserDto
                        {
                           IsActive= Myusers.IsActive,
                           PhoneNumber = Myusers.PhoneNumber,
                           Name= Myusers.Name,
                           Id = Myusers.Id
                        }
                    };

                }
            }
        }

        public User FindUserWithPhonenumber(string PhoneNumber)
        {
            var user = MyContext.Users.Where(p => p.PhoneNumber.Equals(PhoneNumber)).FirstOrDefault();
            return user;
        }

        public User  RegistrUser(string PhoneNumber)
        {
            User user = new User
            {
                IsActive = true,
                PhoneNumber = PhoneNumber
            };
            MyContext.Users.Add(user);
            MyContext.SaveChanges();
            return user;

        }

        public void LogOut(int UserId)
        {
            var Result = MyContext.UserTokens.Where(p => p.User.Id == UserId).ToList();
            MyContext.UserTokens.RemoveRange(Result);
            MyContext.SaveChanges();

        }


    }
}
