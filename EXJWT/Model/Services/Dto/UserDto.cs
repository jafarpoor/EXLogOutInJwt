using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace EXJWT.Model.Entites
{
    public class UserDto
    {
        public int Id { get; set; }
        public string Name { get; set; }
        public bool IsActive { get; set; }
        public string PhoneNumber { get; set; }
        public ICollection<UserTokenDto> userTokens { get; set; } = new List<UserTokenDto>();
    }
}
