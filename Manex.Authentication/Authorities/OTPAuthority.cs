using IdentityServer4.Models;
using Microsoft.Extensions.Logging;
using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using Manex.Authentication.Utility;
using Microsoft.Extensions.Configuration;
using Manex.Authentication.Contracts.Identity;
using Manex.Authentication;
using Microsoft.AspNetCore.Identity;

namespace WebIddentityServer4.Authorities {
    public class OTPAuthority : IAuthority {
        private readonly ILogger _logger;
        private readonly IConfiguration _configuration;
        private readonly IApplicationUserManager _applicationUserManager;

        public OTPAuthority(ILogger logger, IConfiguration configuration, IApplicationUserManager applicationUserManager) {
            _logger = logger;
            _configuration = configuration;
            _applicationUserManager = applicationUserManager;
        }

        public string[] Payload => new string[] { "otp" };

        private Claim[] generateOTPClaims(string phone) {
            var digit = 4;
            var otp = new Random().Next((int)Math.Pow(10, (digit - 1)), (int)Math.Pow(10, digit) - 1).ToString("####");

            string manexAndroidAppToken = _configuration.GetSection("ManexAndroidAppToken").Value;
            var msg = string.Format("Phone number {0} OTP is {1} and Hash is {2}", phone, otp, manexAndroidAppToken);
            _logger.LogInformation(string.Format("\n{0}\n{1}\n{0}\n", new String('*', msg.Length), msg));
            SmsMessageKavehnegar.SendToken(phone, new List<string>() { string.Format("{0}\n\n{1}", otp, manexAndroidAppToken) });
            var sid = DateTime.Now.Ticks.ToString();

            var hash = string.Format("{0}:{1}", sid, otp).Sha256();
            return new Claim[]
            {
                new Claim("otp_id", sid),
                new Claim("otp_hash", hash),
            };
        }

        public Claim[] OnForward(Claim[] claims) {
            var phone = claims.Single(c => c.Type == "phone").Value;
            return generateOTPClaims(phone);
        }

        public Claim[] OnVerify(Claim[] claims, JObject payload, string identifier, out bool valid) {
            Exception ex;
            valid = false;
            var id = claims.Single(c => c.Type == identifier).Value;
            var otpId = claims.Single(c => c.Type == "otp_id").Value;
            var hash = claims.Single(c => c.Type == "otp_hash").Value;
            if (string.Format("{0}:{1}", otpId, payload["otp"].ToString()).Sha256() == hash) {

                if (!string.IsNullOrWhiteSpace(payload["password"]?.ToString())) {
                    var phone = claims.Single(c => c.Type == "phone").Value;
                    var user = _applicationUserManager.FindByNameAsync(phone).Result;

                    var result = _applicationUserManager.ChangePasswordAsync(user, payload["password"].ToString()).Result;

                    if (!result.Succeeded) {
                         ex = new Exception();
                        ex.Data.Add(Gp_Error.IdentityResultFaild, result.Errors.ToList());
                        throw ex;
                    }
                }

                valid = true;
                return new Claim[]
                {
                new Claim(identifier, id)
                };
            }
             ex = new Exception();
            List<IdentityError> errors = new List<IdentityError>();
            errors.Add(new IdentityError {
                Code = nameof(ErrorKey.OtpCodeNotValid),
                Description = ErrorKey.OtpCodeNotValid
            });
            ex.Data.Add(Gp_Error.IdentityResultFaild, errors); 

            throw ex;

        }
    }
}
