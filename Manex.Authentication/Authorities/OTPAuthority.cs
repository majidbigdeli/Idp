﻿using IdentityServer4.Models;
using Microsoft.Extensions.Logging;
using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using Manex.Authentication.Utility;
using Microsoft.Extensions.Configuration;

namespace WebIddentityServer4.Authorities
{
    public class OTPAuthority : IAuthority
    {
        private readonly ILogger _logger;
        private readonly IConfiguration _configuration;
        public OTPAuthority(ILogger logger,IConfiguration configuration)
        {
            _logger = logger;
            _configuration = configuration;
        }

        public string[] Payload => new string[] { "otp" };

        private Claim[] generateOTPClaims(string phone)
        {
            var digit = 4;
            var otp = new Random().Next(0, (int)Math.Pow(10, digit) - 1).ToString("####");
            
            string manexAndroidAppToken = _configuration.GetSection("ManexAndroidAppToken").Value;
            var msg = string.Format("Phone number {0} OTP is {1} and Hash is {2}", phone, otp,manexAndroidAppToken);
            _logger.LogInformation(string.Format("\n{0}\n{1}\n{0}\n", new String('*', msg.Length), msg));
            SmsMessageKavehnegar.SendToken(phone, new List<string>() {string.Format("{0}\n\n{1}",otp,manexAndroidAppToken)});
            var sid = DateTime.Now.Ticks.ToString();

            var hash = string.Format("{0}:{1}", sid, otp).Sha256();
            return new Claim[]
            {
                new Claim("otp_id", sid),
                new Claim("otp_hash", hash)
            };
        }

        public Claim[] OnForward(Claim[] claims)
        {
            var phone = claims.Single(c => c.Type == "phone").Value;
            return generateOTPClaims(phone);
        }

        public Claim[] OnVerify(Claim[] claims, JObject payload, string identifier, out bool valid)
        {
            valid = false;
            var id = claims.Single(c => c.Type == identifier).Value;
            var otpId = claims.Single(c => c.Type == "otp_id").Value;
            var hash = claims.Single(c => c.Type == "otp_hash").Value;
            if (string.Format("{0}:{1}", otpId, payload["otp"].ToString()).Sha256() == hash)
            {
                valid = true;
                return new Claim[]
                {
                new Claim(identifier, id)
                };
            }
            throw new ArgumentException();
        }
    }
}
