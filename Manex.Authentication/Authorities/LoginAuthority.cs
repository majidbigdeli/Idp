using Manex.Authentication.Contracts.Identity;
using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.Security.Claims;

namespace WebIddentityServer4.Authorities
{
    public class LoginAuthority : IAuthority
    {

        private readonly IApplicationUserManager _applicationUserManager;
        private readonly IApplicationSignInManager _applicationSignInManager;

        public LoginAuthority(IApplicationUserManager applicationUserManager,IApplicationSignInManager applicationSignInManager)
        {
            _applicationUserManager = applicationUserManager;
            _applicationSignInManager = applicationSignInManager;
        }

        public string[] Payload => new string[] { "login" };

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

            var result = _applicationSignInManager.CheckPasswordSignInAsync(user, payload["password"].ToString(), true).Result;

            if (!result.Succeeded)
            {
                throw new KeyNotFoundException();

            }

            valid = true;
            return new Claim[]
            {
            new Claim(identifier, user.Id.ToString()),
            };
        }
    }
}
