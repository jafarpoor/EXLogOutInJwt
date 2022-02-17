using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace EXJWT.Model.Services.Dto
{
    public class LoginResultDto
    {
        public string Token { get; set; }
        public string RefreshToken { get; set; }
    }
}
