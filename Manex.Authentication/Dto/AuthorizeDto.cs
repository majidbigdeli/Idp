using System.Collections.Generic;

namespace Manex.Authentication.Dto {
    public class AuthorizeDto {
        public List<string> roles { get; set; }
        public string token { get; set; }
    }


}
