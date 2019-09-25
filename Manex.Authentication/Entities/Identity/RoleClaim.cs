using Manex.Authentication.Entities.AuditableEntity;
using Microsoft.AspNetCore.Identity;

namespace Manex.Authentication.Entities.Identity
{
    public class RoleClaim : IdentityRoleClaim<long>, IAuditableEntity
    {
        public virtual Role Role { get; set; }
    }



}
