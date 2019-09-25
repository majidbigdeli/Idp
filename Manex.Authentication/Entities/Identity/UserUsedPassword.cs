using Manex.Authentication.Entities.AuditableEntity;

namespace Manex.Authentication.Entities.Identity
{
    public class UserUsedPassword : IAuditableEntity
    {
        public long Id { get; set; }

        public string HashedPassword { get; set; }

        public virtual User User { get; set; }
        public long UserId { get; set; }
    }



}
