namespace Manex.Authentication {
    public static class ErrorKey {
        public const string OtpCodeNotValid = "کد وارد شده درست نمی باشد";
        public const string CreateUserFaild = "ایجاد یوزر با مشکل مواجعه شده است";
        public const string ExpireToken = "توکن منقضی شده است";
        public const string UserNotFound = "کاربری پیدا نشد";
        public const string PasswordNotCorrect = "رمز عبور اشتباه می باشد";
        public const string FaildAccessToken = "مشکل در ایجاد توکن";
        public const string AuthroizeFaild = "هدر Authroize اشتباه میباشد";
        public const string Unknown = "خطای ناشناخته";
    }

    public enum Gp_Error {
        IdentityResultFaild,
        Unknown
    }
}
