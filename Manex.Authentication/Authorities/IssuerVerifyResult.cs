namespace WebIddentityServer4.Authorities
{
    public class IssuerVerifyResult
    {
        public string Token { get; set; }
        public string Authority { get; set; }
        public string[] Payload { get; set; }
    }

}
