using IdentityModel;
using Newtonsoft.Json.Linq;
using System;
using System.Linq;
using System.Security.Claims;

namespace WebIddentityServer4.Authorities {
    public class RefreshTokenAuthority : IAuthority {
        public string[] Payload => new string[] { "refreshToken" };

        public Claim[] OnForward(Claim[] claims) {
            throw new NotImplementedException();
        }

        public Claim[] OnVerify(Claim[] claims, JObject payload, string identifier, out bool valid) {
            Exception ex;
            var userId = claims.FirstOrDefault(x => x.Type == ClaimTypes.NameIdentifier).Value;
            valid = true;
            return new Claim[]
            {
            new Claim(identifier,userId),
            };
        }
    }

}
