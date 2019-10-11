using Manex.Authentication.Enum;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using WebIddentityServer4.Authorities;
using WebIddentityServer4.Helpers;

namespace Manex.Authentication.Factory {

    public interface IVerifyFactory {
        IssuerVerifyResult Register(IDictionary<VerifyEnum, IAuthority> authorities, Claim[] verifyClaims, string _identifier, int timeout);
    }

    public class VerifyAccount : IVerifyFactory {

        public IssuerVerifyResult Register(IDictionary<VerifyEnum, IAuthority> authorities, Claim[] verifyClaims, string _identifier ,int timeout) {

            var nextAuthority = authorities[VerifyEnum.otp];
            var forwardClaims = new Claim[] { };
            if (verifyClaims.Any()) {
                forwardClaims = nextAuthority.OnForward(verifyClaims);
            }

            var verifyToken = JwtHelper.GenerateToken(verifyClaims.Concat(forwardClaims).ToArray(), timeout);

            return new IssuerVerifyResult() {
                Token = verifyToken,
            };
        }
    }
    public class AuthAccount : IVerifyFactory {
        private readonly IAuthenticator _authenticator;

        public AuthAccount(IAuthenticator authenticator) {
            _authenticator = authenticator;
        }

        public IssuerVerifyResult Register(IDictionary<VerifyEnum, IAuthority> authorities, Claim[] verifyClaims, string _identifier, int timeout) {
            var identifier = verifyClaims.FirstOrDefault(c => c.Type == _identifier);
            var authenticationClaims = _authenticator.GetAuthenticationClaims(identifier.Value);
            return new IssuerVerifyResult() {
                Token = JwtHelper.GenerateToken(authenticationClaims, timeout),
            };
        }
    }


    public abstract class VerifyFactory {
        public abstract IVerifyFactory Create(IAuthenticator authenticator);
    }

    public class VerifyAccountFactory : VerifyFactory {
        public override IVerifyFactory Create(IAuthenticator authenticator) => new VerifyAccount();
    }

    public class AuthAccountFactory : VerifyFactory {
        public override IVerifyFactory Create(IAuthenticator authenticator) => new AuthAccount(authenticator);
    }

}
