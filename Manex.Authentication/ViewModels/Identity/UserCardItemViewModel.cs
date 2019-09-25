using Manex.Authentication.Entities.Identity;
using System.Collections.Generic;

namespace Manex.Authentication.Identity
{
    public enum UserCardItemActiveTab
    {
        UserInfo,
        UserAdmin
    }

    public class UserCardItemViewModel
    {
        public User User { set; get; }
        public bool ShowAdminParts { set; get; }
        public List<Role> Roles { get; set; }
        public UserCardItemActiveTab ActiveTab { get; set; }
    }
}