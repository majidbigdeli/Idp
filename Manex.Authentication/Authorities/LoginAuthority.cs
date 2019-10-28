using Manex.Authentication;
using Manex.Authentication.Contracts.Identity;
using Microsoft.AspNetCore.Identity;
using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.Security.Claims;

namespace WebIddentityServer4.Authorities {
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
            Exception ex;

            valid = false;
            var user = _applicationUserManager.FindByNameAsync(payload["phone"].ToString()).Result;
            if (user == null)
            {
               ex = new Exception();
                List<IdentityError> errors = new List<IdentityError>();
                errors.Add(new IdentityError {
                    Code = nameof(ErrorKey.UserNotFound),
                    Description = ErrorKey.UserNotFound
                });
                ex.Data.Add(Gp_Error.IdentityResultFaild, errors);
                throw ex;
            }
  
            var result = _applicationSignInManager.CheckPasswordSignInAsync(user, payload["password"].ToString(), true).Result;

            if (!result.Succeeded)
            {
                ex = new Exception();
                List<IdentityError> errors = new List<IdentityError>();
                errors.Add(new IdentityError {
                    Code = nameof(ErrorKey.PasswordNotCorrect),
                    Description = ErrorKey.PasswordNotCorrect
                });
                ex.Data.Add(Gp_Error.IdentityResultFaild, errors);
                throw ex;
            }

            valid = true;
            return new Claim[]
            {
            new Claim(identifier, user.Id.ToString()),
            };
        }
    }

}
