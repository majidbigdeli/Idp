using Manex.Authentication;
using Manex.Authentication.Contracts.Identity;
using Manex.Authentication.Entities.Identity;
using Microsoft.AspNetCore.Identity;
using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.Security.Claims;

namespace WebIddentityServer4.Authorities {
    public class AccountAuthority : IAuthority {
        private readonly IApplicationUserManager _applicationUserManager;

        public AccountAuthority(IApplicationUserManager applicationUserManager) {
            _applicationUserManager = applicationUserManager;
        }

        public string[] Payload => new string[] { "username", "password" };

        public Claim[] OnForward(Claim[] claims) {
            throw new NotImplementedException();
        }

        public Claim[] OnVerify(Claim[] claims, JObject payload, string identifier, out bool valid) {
            valid = false;
            var user = _applicationUserManager.FindByNameAsync(payload["phone"].ToString()).Result;
            if (user == null) {

                user = _applicationUserManager.CreateUserAsync(new User {
                    UserName = payload["phone"].ToString(),
                    IsActive = true,
                    EmailConfirmed = true
                }).Result;

                if (user.Id == default(long)) {

                    Exception ex = new Exception();
                    List<IdentityError> errors = new List<IdentityError>();
                    errors.Add(new IdentityError {
                        Code = nameof(ErrorKey.CreateUserFaild),
                        Description = ErrorKey.CreateUserFaild
                    });
                    ex.Data.Add(Gp_Error.IdentityResultFaild, errors);
                    throw ex;
                } }

            valid = true;
            return new Claim[]
            {
            new Claim(identifier, user.Id.ToString()),
            new Claim("phone", user.PhoneNumber),
            };
        }
    }

}
