using IdentityServer4.Models;
using IdentityServer4.Validation;
using System.Security.Claims;
using System.Threading.Tasks;
using WebIddentityServer4.Helpers;
using static IdentityModel.OidcConstants;

namespace Manex.Authentication
{
    public class AuthenticationGrant : IExtensionGrantValidator
    {
        private static string authSecret = "91c76808-ae3b-4a63-8a61-c2bcda5fe69c";

        public string GrantType => "authentication";

        internal string DeserializeAuthToken(string token)
        {
            var principle = JwtHelper.GetClaimsPrincipal(token);
            if (principle == null)
                return null;
            var identity = principle.Identity as ClaimsIdentity;
            if (identity == null)
                return null;
            if (!identity.IsAuthenticated)
                return null;
            var authKey = identity.FindFirst("auth_key").Value;
            var authHash = identity.FindFirst("auth_hash").Value;
            if (string.Format("{0}:{1}", authKey, authSecret).Sha256() == authHash)
                return authKey;
            return null;
        }

        public Task ValidateAsync(ExtensionGrantValidationContext context)
        {
            context.Result = new GrantValidationResult(TokenErrors.InvalidRequest, "authentication");
            var token = context.Request.Raw.Get("auth_token");
            if (string.IsNullOrEmpty(token))
                return Task.FromResult(context.Result);
            try
            {
                var authKey = DeserializeAuthToken(token);
                if (!string.IsNullOrWhiteSpace(authKey))
                    context.Result = new GrantValidationResult(authKey, "authentication");
                return Task.FromResult(context.Result);
            }
            catch
            {
                return Task.FromResult(context.Result);
            }
        }
    }


}
