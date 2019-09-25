using Manex.Authentication.Entities.AuditableEntity;
using Microsoft.AspNetCore.Identity;

namespace Manex.Authentication.Entities.Identity
{
    public class UserLogin : IdentityUserLogin<long>, IAuditableEntity
    {
        public virtual User User { get; set; }
    }



}
