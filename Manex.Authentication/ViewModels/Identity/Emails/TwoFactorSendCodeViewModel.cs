namespace Manex.Authentication.Identity.Emails
{
    public class TwoFactorSendCodeViewModel : EmailsBase
    {
        public string Token { set; get; }
    }
}