using Manex.Authentication.Entities.AuditableEntity;
using Microsoft.AspNetCore.Identity;

namespace Manex.Authentication.Entities.Identity
{
    public class UserToken : IdentityUserToken<long>, IAuditableEntity
    {
        public virtual User User { get; set; }
    }



}
