using IdentityServer4.Models;
using Manex.Authentication;
using Microsoft.IdentityModel.Tokens;
using System;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;

namespace WebIddentityServer4.Helpers {
    public class JwtHelper {
        private static string Secret = "jwtsecret".Sha256();

        public static string GenerateToken(Claim[] claims, int timeout) {
            var symmetricKey = Convert.FromBase64String(Secret);
            var tokenHandler = new JwtSecurityTokenHandler();

            var now = DateTime.UtcNow;
            var tokenDescriptor = new SecurityTokenDescriptor {
                Subject = new ClaimsIdentity(claims),
                Expires = now.AddSeconds(timeout),
                SigningCredentials = new SigningCredentials(RsaSecurityKeyManager.getInstance(), SecurityAlgorithms.RsaSha256)
            };

            var stoken = tokenHandler.CreateToken(tokenDescriptor);
            var token = tokenHandler.WriteToken(stoken);

            return token;
        }

        public static ClaimsPrincipal GetClaimsPrincipal(string token) {
            var tokenHandler = new JwtSecurityTokenHandler();
            var jwtToken = tokenHandler.ReadToken(token) as JwtSecurityToken;

            if (jwtToken == null)
                return null;

            var symmetricKey = Convert.FromBase64String(Secret);
            var validationParameters = new TokenValidationParameters() {
                ClockSkew = TimeSpan.Zero,
                RequireExpirationTime = true,
                ValidateIssuer = false,
                ValidateAudience = false,
                IssuerSigningKey = RsaSecurityKeyManager.getInstance()
        };
            try {
                return tokenHandler.ValidateToken(token, validationParameters, out SecurityToken securityToken);
            } catch (Exception e) {
                return null;
            }
        }
    }
}
