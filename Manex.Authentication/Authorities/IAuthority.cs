using Newtonsoft.Json.Linq;
using System.Security.Claims;

namespace WebIddentityServer4.Authorities
{
    public interface IAuthority
    {
        string[] Payload { get; }
        Claim[] OnVerify(Claim[] claims, JObject payload, string identifier, out bool valid);
        Claim[] OnForward(Claim[] claims);
    }
}
