using Manex.Authentication.Enum;

namespace WebIddentityServer4.Authorities
{
    public static class AuthorityIssuerExtension
    {
        public static AuthorityIssuer Register(this AuthorityIssuer issuer, VerifyEnum name, IAuthority authority, int timeout = 60)
        {
            issuer.Register(authority,name, timeout);
            return issuer;
        }
    }

}
