using IdentityModel;
using IdentityServer4.Extensions;
using IdentityServer4.Models;
using IdentityServer4.Services;
using IdentityServer4.Validation;
using Manex.Authentication.Entities.Identity;
using Microsoft.AspNetCore.Identity;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;

namespace Manex.Authentication.Services.Identity {

    public class ResourceOwnerPasswordValidator : IResourceOwnerPasswordValidator {
        private readonly UserManager<User> _userManager;

        public ResourceOwnerPasswordValidator(UserManager<User> userManager) {
            _userManager = userManager;
        }

        public Task ValidateAsync(ResourceOwnerPasswordValidationContext context) {
            var userTask = _userManager.FindByNameAsync(context.UserName);
            var user = userTask.Result;

            context.Result = new GrantValidationResult(user.Id.ToString(), "Password", null, "local", null);
            return Task.FromResult(context.Result);
        }
    }

    public class AspNetIdentityProfileService : IProfileService {
        private readonly UserManager<User> _userManager;
        private readonly IUserClaimsPrincipalFactory<User> _claimsFactory;

        public AspNetIdentityProfileService(IUserClaimsPrincipalFactory<User> claimsFactory, UserManager<User> userManager) {
            _userManager = userManager;
            _claimsFactory = claimsFactory;
        }

        public async Task GetProfileDataAsync(ProfileDataRequestContext context) {

            var sub = context.Subject.GetSubjectId();
            var user = await _userManager.FindByIdAsync(sub);
            if (user == null) {
                throw new ArgumentException("");
            }

            var principal = await _claimsFactory.CreateAsync(user);
            var claims = principal.Claims.ToList();

            //Add more claims like this
            claims.Add(new System.Security.Claims.Claim("username", user.UserName));

            context.IssuedClaims = claims;


            // var subject = context.Subject;
            // if (subject == null) throw new ArgumentNullException(nameof(context.Subject));

            // var subjectId = subject.GetSubjectId();

            // var user = await _userManager.FindByIdAsync(subjectId);
            // if (user == null)
            //     throw new ArgumentException("Invalid subject identifier");

            // var claims = await GetClaimsFromUser(user);

           // var siteIdClaim = claims.FirstOrDefault(x => x.Type == "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress");
            // context.IssuedClaims.Add(new Claim(JwtClaimTypes.Email, user.Email));
            //// context.IssuedClaims.Add(new Claim("siteid", siteIdClaim.Value));
            // context.IssuedClaims.Add(new Claim(JwtClaimTypes.Role, user.Roles));

            // var roleClaims = claims.Where(x => x.Type == "http://schemas.microsoft.com/ws/2008/06/identity/claims/role");
            // foreach (var roleClaim in roleClaims) {
            //     context.IssuedClaims.Add(new Claim(JwtClaimTypes.Role, roleClaim.Value));
            // }
        }

        public async Task IsActiveAsync(IsActiveContext context) {
            var subject = context.Subject;
            if (subject == null) throw new ArgumentNullException(nameof(context.Subject));

            var subjectId = subject.GetSubjectId();
            var user = await _userManager.FindByIdAsync(subjectId);

            context.IsActive = false;

            if (user != null) {
                if (_userManager.SupportsUserSecurityStamp) {
                    var security_stamp = subject.Claims.Where(c => c.Type == "security_stamp").Select(c => c.Value).FirstOrDefault();
                    if (security_stamp != null) {
                        var db_security_stamp = await _userManager.GetSecurityStampAsync(user);
                        if (db_security_stamp != security_stamp)
                            return;
                    }
                }

                context.IsActive =
                    !user.LockoutEnabled ||
                    !user.LockoutEnd.HasValue ||
                    user.LockoutEnd <= DateTime.Now;
            }
        }

        private async Task<IEnumerable<Claim>> GetClaimsFromUser(User user) {
            var claims = new List<Claim>
            {
            new Claim(JwtClaimTypes.Subject, user.Id.ToString()),
            new Claim(JwtClaimTypes.PreferredUserName, user.UserName)
        };

            if (_userManager.SupportsUserEmail) {
                claims.AddRange(new[]
                {
                new Claim(JwtClaimTypes.Email, user.Email),
                new Claim(JwtClaimTypes.EmailVerified, user.EmailConfirmed ? "true" : "false", ClaimValueTypes.Boolean)
            });
            }

            if (_userManager.SupportsUserPhoneNumber && !string.IsNullOrWhiteSpace(user.PhoneNumber)) {
                claims.AddRange(new[]
                {
                new Claim(JwtClaimTypes.PhoneNumber, user.PhoneNumber),
                new Claim(JwtClaimTypes.PhoneNumberVerified, user.PhoneNumberConfirmed ? "true" : "false", ClaimValueTypes.Boolean)
            });
            }

            if (_userManager.SupportsUserClaim) {
                claims.AddRange(await _userManager.GetClaimsAsync(user));
            }

            if (_userManager.SupportsUserRole) {
                var roles = await _userManager.GetRolesAsync(user);
                claims.AddRange(roles.Select(role => new Claim(ClaimTypes.NameIdentifier, role)));
            }

            return claims;
        }
    }
       
}
