using EXJWT.Model.Entites;
using Microsoft.EntityFrameworkCore;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace EXJWT.Model.Context
{
    public class DataBaseContext :DbContext
    {
        public DataBaseContext(DbContextOptions options) : base(options)
        {

        }
        public DbSet<User> Users { get; set; }

        public DbSet<UserToken> UserTokens { get; set; }
        public DbSet<SmsCode> smsCodes { get; set; }
    }
}
