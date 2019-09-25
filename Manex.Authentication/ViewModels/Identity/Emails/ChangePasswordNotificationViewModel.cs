using Manex.Authentication.Entities.Identity;

namespace Manex.Authentication.Identity.Emails
{
    public class ChangePasswordNotificationViewModel : EmailsBase
    {
        public User User { set; get; }
    }
}