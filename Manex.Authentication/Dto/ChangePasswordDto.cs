using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace Manex.Authentication.Dto {

    public class ChangePasswordDto {
        public string CurrentPassword { get; set; }
        public string NewPassword { get; set; }
    }

    public class SetUserRoles {
        public long UserId { get; set; }
        public List<long> RoleIds { get; set; }
    }

}
