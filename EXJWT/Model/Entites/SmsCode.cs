using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace EXJWT.Model.Entites
{
    public class SmsCode
    {
        public int Id { get; set; }
        public string PhoneNumber { get; set; }
        public string Code { get; set; }
        public int RequestCount { get; set; }
        public bool UsedCode { get; set; }
        public DateTime InsertTime { get; set; }
    }
}
