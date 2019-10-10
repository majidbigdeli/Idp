using Manex.Authentication.Contracts.Identity;
using Manex.Authentication.Dto;
using Manex.Authentication.Entities.Identity;
using Manex.Authentication.Factory;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using WebIddentityServer4.Authorities;
using WebIddentityServer4.Helpers;

namespace Manex.Authentication.Controllers {

    public class AuthorityModel {
        public JObject payload { get; set; }
        public string token { get; set; }
    }

    [ApiController]
    [Produces("application/json")]
    [Route("api/[controller]")]
    public class AuthorityController : Controller {
        private readonly IApplicationUserManager _applicationUserManager;
        private readonly IApplicationRoleManager _applicationRoleManager;
        private Dictionary<string, AuthorityIssuer> _issuers;

        public AuthorityController(IApplicationUserManager applicationUserManager,
            IApplicationSignInManager applicationSignInManager,
            IApplicationRoleManager applicationRoleManager,
            ILogger<AuthorityController> logger, IConfiguration configuration) {
            _applicationUserManager = applicationUserManager;
            _applicationRoleManager = applicationRoleManager;
            _issuers = new Dictionary<string, AuthorityIssuer>()
            {
                {
                    "owner",
                    AuthorityIssuer.Create(new AuthenticationAuthority(), "identity")
                        .Register("account", new AccountAuthority(applicationUserManager))
                        .Register("otp", new OTPAuthority(logger,configuration,applicationUserManager))
                        .Register("login",new LoginAuthority(applicationUserManager,applicationSignInManager))
                }
            };
        }


        #region OtpLogin

        [HttpPost("GetOtp")]
        public async Task<IActionResult> GetOtp(OtpDto otpDto) {

            dynamic jsonObject = new JObject();
            jsonObject.phone = otpDto.Phone;

            AuthorityModel model = new AuthorityModel() {
                payload = jsonObject,
                token = ""
            };
            return await Auth("", model);
        }


        [HttpPost("OtpLogin")]
        public async Task<IActionResult> OtpLogin(OtpLoginDto otpLoginDto) {

            dynamic jsonObject = new JObject();
            jsonObject.otp = otpLoginDto.Otp;

            AuthorityModel model = new AuthorityModel() {
                payload = jsonObject,
                token = otpLoginDto.Token
            };
            return await Auth("otp", model);
        }

        #endregion


        #region UserPassLogin

        [HttpPost("UserPassLogin")]
        public async Task<IActionResult> UserPassLogin(UserPassDto userPassDto) {
            dynamic jsonObject = new JObject();
            jsonObject.phone = userPassDto.Phone;
            jsonObject.password = userPassDto.Password;

            AuthorityModel model = new AuthorityModel() {
                payload = jsonObject,
                token = ""
            };
            return await Auth("login", model);
        }
        #endregion


        #region ForgotPassword

        [HttpPost("OtpForgotPassword")]
        public async Task<IActionResult> OtpForgotPassword(OtpDto otpForgotDto) {
            return await GetOtp(otpForgotDto);
        }

        [HttpPost("OtpResetPassword")]
        public async Task<IActionResult> OtpResetPassword(OtpUpdatePasswordDto otpUpdatePassword) {
            dynamic jsonObject = new JObject();
            jsonObject.otp = otpUpdatePassword.Otp;
            jsonObject.password = otpUpdatePassword.NewPassword;
            AuthorityModel model = new AuthorityModel() {
                payload = jsonObject,
                token = otpUpdatePassword.Token
            };
            return await Auth("otp", model);
        }

        #endregion

        #region PasswordChange
        [ManexAuthorize]
        [HttpPost("ChangePassword")]
        public async Task<IActionResult> ChangePassword(ChangePasswordDto changePasswordDto) {
            string auth_token = Request.Headers["Authroize"].ToString();
            long userId = GetUserIdFromAuthToken(auth_token);
            if (userId == default(long)) {
                return Ok(new { Status = false });
            }

            var result = await _applicationUserManager.ChangePasswordAsync(_applicationUserManager.FindById(userId), changePasswordDto.CurrentPassword, changePasswordDto.NewPassword);

            if (!result.Succeeded) {
                return Ok(new { Status = false });
            }
            return Ok(new { Status = true });
        }

        #endregion

        #region role

        [ManexAuthorize(new string[] { "Admin" })]
        [HttpPost("CreateRole")]
        public async Task<IActionResult> CreateRole(CreateRoleDto createRoleDto) {
            var res = await _applicationRoleManager.CreateAsync(new Role() {
                Name = createRoleDto.Name,
            });
            return Ok(new { Status = res.Succeeded });
        }

        [HttpPost("SetUserRole")]
        public async Task<IActionResult> SetUserRole(SetUserRoles setUserRoles) {

         var result = await  _applicationUserManager.SetUserRole(setUserRoles.UserId, setUserRoles.RoleIds);

            return Ok(new { Status = result });
        }


        #endregion


        [HttpPost("Register")]
        public async Task<IActionResult> Register(RegisterUserDto registerUserDto) {

            IRegisterUserFactory factory;
            bool result = false;
            switch (string.IsNullOrWhiteSpace(registerUserDto.Password)) {
                case true:
                    factory = new RegisterUserWithoutPasswordFactory().Create(registerUserDto, _applicationUserManager);
                    result = await factory.Register();
                    break;
                case false:
                    factory = new RegisterUserWithPasswordFactory().Create(registerUserDto, _applicationUserManager);
                    result = await factory.Register();
                    break;
            }

            return Ok(new { Status = result });
        }


        #region ManexAuthorize Attribute api

        [HttpPost("Authorize")]
        public IActionResult Authorize(AuthorizeDto authorizeDto) {
            long userId = GetUserIdFromAuthToken(authorizeDto.token);
            if (userId == default(long)) {
                return Ok(false);
            }
            var roles = _applicationRoleManager.GetRolesForUser(userId).Select(x => x.Name.ToUpper()).ToList();

            if (!roles.Except(authorizeDto.roles).Any()) {
                return Ok(true);
            }
            return Ok(false);
        }

        #endregion


        #region Private

        [NonAction]
        private async Task<IActionResult> Auth(string authority, AuthorityModel model) {
            if (model == null || model?.payload == null)
                return Unauthorized();
            var authorities = _issuers["owner"].Authorities;
            if (!authorities.Any())
                return Unauthorized();
            string token = model.token;
            if (string.IsNullOrWhiteSpace(authority)) {
                authority = authorities.Keys.ToArray()[0];
            }
            if (string.IsNullOrWhiteSpace(token)) {
                token = JwtHelper.GenerateToken(new Claim[] { }, 60);
            }
            if (string.IsNullOrWhiteSpace(token))
                return Unauthorized();
            var principle = JwtHelper.GetClaimsPrincipal(token);

            if (principle?.Identity?.IsAuthenticated == true) {
                try {
                    var claimsIdentity = principle.Identity as ClaimsIdentity;
                    var verifyResult = _issuers["owner"].Verify(authority, claimsIdentity.Claims.ToArray(), model.payload);
                    if (verifyResult.Authority == null) {
                        IEnumerable<KeyValuePair<string, string>> keyValuePairs = new Dictionary<string, string> {
                            {"grant_type","authentication" },{"client_id","Authentication"},{"client_secret","clientsecret"},{"scope","api.sample offline_access"},{"auth_token",verifyResult.Token}
                             };
                        var domin = ContextHelper.GetDomin();
                        AccesToken accesToken = await HttpClientHelper.PostFormUrlEncoded<AccesToken>($"{domin.AbsoluteUri}connect/token", keyValuePairs);
                        accesToken.auth_token = StringCipher.Encrypt(verifyResult.Token);
                        return Ok(accesToken);


                    }
                    return Ok(new { verify_token = verifyResult.Token, authority = verifyResult.Authority, parameters = verifyResult.Payload });
                } catch (Exception e) {
                    return Unauthorized();
                }
            }

            return Unauthorized();

        }

        private long GetUserIdFromAuthToken(string encriptToken) {
            var auth_token = StringCipher.Decrypt(encriptToken);
            var principle = JwtHelper.GetClaimsPrincipal(auth_token);
            if (principle?.Identity?.IsAuthenticated == true) {
                var claimsIdentity = principle.Identity as ClaimsIdentity;
                var userId = claimsIdentity.Claims.FirstOrDefault(x => x.Type == "userId").Value;
                if (string.IsNullOrWhiteSpace(userId)) {
                    return default(long);
                }
                return long.Parse(userId);
            }
            return default(long);
        }

        #endregion
    }

}