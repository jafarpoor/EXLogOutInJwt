using System;

namespace EXJWT.Model.Entites
{
    public class UserTokenDto
    {
        public int Id { get; set; }
        public string HashToken { get; set; }
        public DateTime ExpTime { get; set; }
        public string MobilModel { get; set; }
        public UserDto User { get; set; }
        public int UserId { get; set; }
        public string RefrshToken { get; set; }
        public DateTime RefrshTokenExp { get; set; }
    }
}
