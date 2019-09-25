using Manex.Authentication.Entities.AuditableEntity;
using Microsoft.AspNetCore.Identity;
using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
using System.Linq;
using System.Threading.Tasks;

namespace Manex.Authentication.Entities.Identity
{
    public class User : IdentityUser<long>, IAuditableEntity
    {
        public User()
        {
            UserUsedPasswords = new HashSet<UserUsedPassword>();
            UserTokens = new HashSet<UserToken>();
        }

        [StringLength(450)]
        public string FirstName { get; set; }

        [StringLength(450)]
        public string LastName { get; set; }

        [NotMapped]
        public string DisplayName
        {
            get
            {
                var displayName = $"{FirstName} {LastName}";
                return string.IsNullOrWhiteSpace(displayName) ? UserName : displayName;
            }
        }

        [Required]
        public override string PhoneNumber { get => this.UserName; set => value = this.UserName ;}


        [Required]
        public override string UserName { get; set; }

        [StringLength(450)]
        public string PhotoFileName { get; set; }

        public DateTimeOffset? BirthDate { get; set; }

        public DateTimeOffset? CreatedDateTime { get; set; }

        public DateTimeOffset? LastVisitDateTime { get; set; }

        public bool IsEmailPublic { get; set; }

        public string Location { set; get; }

        public bool IsActive { get; set; } = true;

        public virtual ICollection<UserUsedPassword> UserUsedPasswords { get; set; }

        public virtual ICollection<UserToken> UserTokens { get; set; }

        public virtual ICollection<UserRole> Roles { get; set; }

        public virtual ICollection<UserLogin> Logins { get; set; }

        public virtual ICollection<UserClaim> Claims { get; set; }
    }

}
