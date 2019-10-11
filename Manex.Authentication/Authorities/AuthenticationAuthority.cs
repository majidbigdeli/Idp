using IdentityServer4.Models;
using System;
using System.Security.Claims;

namespace WebIddentityServer4.Authorities
{
    public class AuthenticationAuthority : IAuthenticator
    {
        private static string authSecret = "91c76808-ae3b-4a63-8a61-c2bcda5fe69c";

        public Claim[] GetAuthenticationClaims(string identifier)
        {
            if (!long.TryParse(identifier, out long guid))
                throw new FormatException();
            var hash = string.Format("{0}:{1}", identifier, authSecret).Sha256();
            return new Claim[]
            {
            new Claim("auth_key", identifier),
            new Claim("auth_hash", hash),
            new Claim("userId", identifier)
            };
        }
    }

}
