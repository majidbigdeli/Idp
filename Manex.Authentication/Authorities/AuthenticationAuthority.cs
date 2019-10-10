using IdentityServer4.Models;
using System;
using System.Security.Claims;

namespace WebIddentityServer4.Authorities
{
    public class AuthenticationAuthority : IAuthenticator
    {
        private static string authSecret = "authenticationsecretkey".Sha256();

        public Claim[] GetAuthenticationClaims(string identifier)
        {
            if (!long.TryParse(identifier, out long guid))
                throw new FormatException();
            var hash = string.Format("{0}:{1}", identifier, authSecret).Sha256();
            return new Claim[]
            {
            new Claim("userId", identifier),
            };
        }
    }

}
