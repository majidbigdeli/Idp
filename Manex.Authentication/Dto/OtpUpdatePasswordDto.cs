namespace Manex.Authentication.Dto {
    public class OtpUpdatePasswordDto {
        public string Otp { get; set; }
        public string Token { get; set; }
        public string NewPassword { get; set; }
    }


}
