using Manex.Authentication.Entities.AuditableEntity;
using Microsoft.AspNetCore.Identity;

namespace Manex.Authentication.Entities.Identity
{
    public class UserRole : IdentityUserRole<long>, IAuditableEntity
    {
        public virtual User User { get; set; }

        public virtual Role Role { get; set; }
    }



}
