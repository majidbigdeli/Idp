using Microsoft.IdentityModel.Tokens;
using System.Security.Cryptography;

namespace Manex.Authentication {
    public static class RsaSecurityKeyManager {
        private static RsaSecurityKey _instance;
        public static RsaSecurityKey getInstance() {
            if (_instance == null) {
                var rsa = new RSACryptoServiceProvider(2048);
                _instance = new RsaSecurityKey(rsa);
            }
            return _instance;
        }
    }



    }