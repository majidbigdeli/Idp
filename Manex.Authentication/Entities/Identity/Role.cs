using Manex.Authentication.Entities.AuditableEntity;
using Microsoft.AspNetCore.Identity;
using System.Collections.Generic;

namespace Manex.Authentication.Entities.Identity
{
    public class Role : IdentityRole<long>, IAuditableEntity
    {
        public Role()
        {
        }

        public Role(string name)
            : this()
        {
            Name = name;
        }

        public Role(string name, string description)
            : this(name)
        {
            Description = description;
        }

        public string Description { get; set; }

        public virtual ICollection<UserRole> Users { get; set; }

        public virtual ICollection<RoleClaim> Claims { get; set; }
    }



}
