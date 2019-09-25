
using Manex.Authentication.Entities.Identity;

namespace Manex.Authentication.Identity.Emails
{
    public class UserProfileUpdateNotificationViewModel : EmailsBase
    {
        public User User { set; get; }
    }
}