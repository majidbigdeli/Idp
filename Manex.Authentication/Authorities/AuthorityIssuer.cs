using Manex.Authentication.Enum;
using Manex.Authentication.Factory;
using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using WebIddentityServer4.Helpers;

namespace WebIddentityServer4.Authorities
{
    public class AuthorityIssuer
    {
        private string _identifier;
        private IAuthenticator _authenticator;
        private IDictionary<VerifyEnum, IAuthority> _authorities = new Dictionary<VerifyEnum, IAuthority>();
        private IDictionary<VerifyEnum, int> _timeouts = new Dictionary<VerifyEnum, int>();

        public IDictionary<VerifyEnum, IAuthority> Authorities
        {
            get { return _authorities; }
        }

        public AuthorityIssuer(IAuthenticator authenticator, string identifier)
        {
            _authenticator = authenticator;
            _identifier = identifier;
        }
        public static AuthorityIssuer Create(IAuthenticator authenticator, string identifier)
        {
            return new AuthorityIssuer(authenticator, identifier);
        }

        internal void Register(IAuthority authority, VerifyEnum name, int timeout)
        {
            _authorities.Add(name, authority);
            _timeouts.Add(name, timeout);
        }

        public IssuerVerifyResult Verify(VerifyEnum authority, Claim[] claims, JObject payload)
        {
            var verifyAuthority = _authorities[authority];
            var verifyClaims = verifyAuthority.OnVerify(claims, payload, _identifier, out bool valid);

            IVerifyFactory verifyFactory;
            IssuerVerifyResult issuerVerifyResult = new IssuerVerifyResult();
            switch (authority) {
                case VerifyEnum.account:
                    verifyFactory = new VerifyAccountFactory().Create(_authenticator);
                    issuerVerifyResult = verifyFactory.Register(_authorities, verifyClaims, _identifier, _timeouts[VerifyEnum.account]);
                    break;
                case VerifyEnum.otp:
                    verifyFactory = new AuthAccountFactory().Create(_authenticator);
                    issuerVerifyResult = verifyFactory.Register(_authorities, verifyClaims, _identifier, _timeouts[VerifyEnum.otp]);
                    break;
                case VerifyEnum.login:
                    verifyFactory = new AuthAccountFactory().Create(_authenticator);
                    issuerVerifyResult = verifyFactory.Register(_authorities, verifyClaims, _identifier, _timeouts[VerifyEnum.login]);
                    break;
                case VerifyEnum.refreshToken:
                    verifyFactory = new AuthAccountFactory().Create(_authenticator);
                    issuerVerifyResult = verifyFactory.Register(_authorities, verifyClaims, _identifier, _timeouts[VerifyEnum.refreshToken]);
                    break;
            }
            return issuerVerifyResult;

        }
    }

}
