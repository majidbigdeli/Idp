namespace Manex.Authentication.Dto {
    public class AccesToken {
        public string access_token { get; set; }
        public string auth_token { get; set; }
        public int expires_in { get; set; }
        public string token_type { get; set; }
        public string refresh_token { get; set; }
    }


}
