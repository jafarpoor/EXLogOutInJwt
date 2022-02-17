using EXJWT.Model.Entites;

namespace EXJWT.Model.Services.Repository
{
    public partial class UserRepository
    {
        public class LoginDto
        {
            public bool IsSuccess { get; set; }
            public string Message { get; set; }
            public UserDto MyUser { get; set; }
        }
            
    }
}
