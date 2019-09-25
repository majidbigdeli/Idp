using System.Security.Claims;

namespace WebIddentityServer4.Authorities
{
    public interface IAuthenticator
    {
        Claim[] GetAuthenticationClaims(string identifier);
    }
}
