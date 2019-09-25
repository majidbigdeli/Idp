using Manex.Authentication.Contracts.Identity;
using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.Security.Claims;
using WebIddentityServer4.Repositories;

namespace WebIddentityServer4.Authorities
{
    public class AccountAuthority : IAuthority
    {
        private readonly IApplicationUserManager _applicationUserManager;

        public AccountAuthority(IApplicationUserManager applicationUserManager)
        {
            _applicationUserManager = applicationUserManager;
        }

        public string[] Payload => new string[] { "username", "password" };

        public Claim[] OnForward(Claim[] claims)
        {
            throw new NotImplementedException();
        }

        public Claim[] OnVerify(Claim[] claims, JObject payload, string identifier, out bool valid)
        {
            valid = false;
            var user = _applicationUserManager.FindByNameAsync(payload["phone"].ToString()).Result;
            if (user == null)
            {
                throw new KeyNotFoundException();
            }

            if (!user.IsActive)
            {
                throw new KeyNotFoundException();
            }

            valid = true;
            return new Claim[]
            {
            new Claim(identifier, user.Id.ToString()),
            new Claim("phone", user.PhoneNumber)
            };

        }
    }

}
