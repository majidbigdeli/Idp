using Manex.Authentication.Contracts.Identity;
using Manex.Authentication.Dto;
using Manex.Authentication.Entities.Identity;
using Manex.Authentication.Enum;
using Manex.Authentication.Factory;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
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
        private readonly int _timeout;

        private Dictionary<string, AuthorityIssuer> _issuers;

        public AuthorityController(IApplicationUserManager applicationUserManager,
            IApplicationSignInManager applicationSignInManager,
            IApplicationRoleManager applicationRoleManager,
            ILogger<AuthorityController> logger, IConfiguration configuration) {
             _timeout = configuration.GetValue<int>("Expire:VerifyNumberLifeTime");
            _applicationUserManager = applicationUserManager;
            _applicationRoleManager = applicationRoleManager;
            _issuers = new Dictionary<string, AuthorityIssuer>()
            {
                {
                    "owner",
                    AuthorityIssuer.Create(new AuthenticationAuthority(), "identity")
                        .Register(VerifyEnum.account, new AccountAuthority(applicationUserManager),_timeout)
                        .Register(VerifyEnum.otp, new OTPAuthority(logger,configuration,applicationUserManager),_timeout)
                        .Register(VerifyEnum.login,new LoginAuthority(applicationUserManager,applicationSignInManager),_timeout)
                        .Register(VerifyEnum.refreshToken,new RefreshTokenAuthority(),_timeout)

                }
            };
        }


        #region OtpLogin

        [HttpPost("GetOtp")]
        public async Task<IActionResult> GetOtp(OtpDto otpDto)
        {
            dynamic jsonObject = new JObject();
            try
            {
                jsonObject.phone = otpDto.Phone;

                AuthorityModel model = new AuthorityModel() {
                    payload = jsonObject,
                    token = ""
                    };
                return Ok(await Auth(VerifyEnum.account, model));
            }
            catch (Exception e)
            {
                return Ok(e.Message);
            }
        }


        [HttpPost("OtpLogin")]
        public async Task<IActionResult> OtpLogin(OtpLoginDto otpLoginDto) {

            dynamic jsonObject = new JObject();
            jsonObject.otp = otpLoginDto.Otp;

            AuthorityModel model = new AuthorityModel() {
                payload = jsonObject,
                token = otpLoginDto.Token
            };
            return Ok(await Auth(VerifyEnum.otp, model));
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
            return Ok(await Auth(VerifyEnum.login, model));
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
            return Ok(await Auth(VerifyEnum.otp, model));
        }

        #endregion

        #region PasswordChange
//        [ManexAuthorize] // دصورت استفاده ار این اتریبیوت باید  auth_token در هدر ست شود
//        [HttpPost("ChangePassword")]
//        public async Task<IActionResult> ChangePassword(ChangePasswordDto changePasswordDto) {
//            string auth_token = Request.Headers["Authroize"].ToString();
//            long userId = GetUserIdFromAuthToken(auth_token);
//            if (userId == default(long)) {
//                return RefreshTokenAuthNotVaild();
//            }
//            var result = await _applicationUserManager.ChangePasswordAsync(_applicationUserManager.FindById(userId), changePasswordDto.CurrentPassword, changePasswordDto.NewPassword);
//            if (!result.Succeeded) {
//                return RefreshTokenResultFaild(result);
//            }
//            return Ok(new ReturnDto() {
//                Data = null,
//                ErrorData = null,
//                Status = true
//            });
//        }


        [ManexWithoutApiCallAuthorize] // دصورت استفاده ار این اتریبیوت باید  auth_token در هدر ست شود
        [HttpPost("ChangePassword")]//ChangePasswordDefault
        public async Task<IActionResult> ChangePassword(ChangePasswordDto changePasswordDto) {
            long userId = long.Parse(HttpContext.User.Claims.Where(x => x.Type == ClaimTypes.NameIdentifier).FirstOrDefault().Value);
            //sample for getting custom claims
//            var username = HttpContext.User.Claims.FirstOrDefault(x => x.Type == "username").Value;
            if (userId == default(long)) {
                return RefreshTokenAuthNotVaild();
            }

            var result = await _applicationUserManager.ChangePasswordAsync(_applicationUserManager.FindById(userId), changePasswordDto.CurrentPassword, changePasswordDto.NewPassword);

            if (!result.Succeeded) {
                return RefreshTokenResultFaild(result);
            }
            return Ok(new ReturnDto() {
                Data = null,
                ErrorData = null,
                Status = true
            });
        }


        #endregion

        #region role

       // [ManexAuthorize(new string[] { "Admin" })]
       [ManexWithoutApiCallAuthorize]
        [HttpPost("CreateRole")]
        public async Task<IActionResult> CreateRole(CreateRoleDto createRoleDto) {
            var res = await _applicationRoleManager.CreateAsync(new Role() {
                Name = createRoleDto.Name,
            });
            if (!res.Succeeded) {
                List<ErrorDto> errorDto = new List<ErrorDto>();
                foreach (var item in res.Errors.ToList()) {
                    errorDto.Add(new ErrorDto() {
                        Description = item.Description,
                        Key = item.Code
                    });
                }
            }

            return Ok(new ReturnDto() {
                Data = null,
                ErrorData = null,
                Status = true
            });
        }

        [HttpPost("SetUserRole")]
        public async Task<IActionResult> SetUserRole(SetUserRoles setUserRoles) {

            var result = await _applicationUserManager.SetUserRole(setUserRoles.UserId, setUserRoles.RoleIds);

            return Ok(new ReturnDto() {
                Data = null,
                ErrorData = null,
                Status = result
            });
        }

        #endregion

        #region Register
        [HttpPost("Register")]
        public async Task<IActionResult> Register(RegisterUserDto registerUserDto) {

            IRegisterUserFactory factory;
            IdentityResult result = new IdentityResult();
            switch (string.IsNullOrWhiteSpace(registerUserDto.Password)) {
                case true:
                    factory = new RegisterUserWithoutPasswordFactory().Create(registerUserDto, _applicationUserManager,_applicationRoleManager);
                    result = await factory.Register();
                    break;
                case false:
                    factory = new RegisterUserWithPasswordFactory().Create(registerUserDto, _applicationUserManager,_applicationRoleManager);
                    result = await factory.Register();
                    break;
            }

            if (!result.Succeeded) {
                List<ErrorDto> errorDto = new List<ErrorDto>();
                foreach (var item in result.Errors.ToList()) {
                    errorDto.Add(new ErrorDto() {
                        Description = item.Description,
                        Key = item.Code
                    });
                }
                return Ok(new ReturnDto() {
                    Data = null,
                    ErrorData = errorDto,
                    Status = false
                });
            }

            return Ok(new ReturnDto() {
                Data = null,
                ErrorData = null,
                Status = true
            });
        }
        #endregion

        #region RefreshToken
//        [HttpPost("RefreshTokenWithAuthToken")]
//        public async Task<IActionResult> RefreshTokenWithAuthToken(RefreshTokenDto refreshTokenDto) {
//
//            IEnumerable<KeyValuePair<string, string>> keyValuePairs = new Dictionary<string, string> {
//                            {"grant_type","refresh_token" },{"client_id","Authentication"},{"client_secret","clientsecret"},{"scope","api.sample offline_access"},{"refresh_token",refreshTokenDto.RefreshToken}
//                             };
//            var domin = ContextHelper.GetDomin();
//            AccesToken accesToken = await HttpClientHelper.PostFormUrlEncoded<AccesToken>($"{domin.AbsoluteUri}connect/token", keyValuePairs);
//
//            dynamic jsonObject = new JObject();
//
//            if (!string.IsNullOrWhiteSpace(accesToken.access_token)) {
//                AuthorityModel model = new AuthorityModel() {
//                    payload = jsonObject,
//                    token = accesToken.access_token
//                };
//                var resut = await Auth(VerifyEnum.refreshToken, model);
//                if (!resut.Status) {
//                    return FaildAccessToken();
//                }
//
//                accesToken.auth_token = StringCipher.Encrypt(resut.Data.verify_token);
//
//                return Ok(new ReturnDto() {
//                    Data = accesToken,
//                    ErrorData = null,
//                    Status = true
//                });
//            }
//            
//                return Ok(new ReturnDto() {
//                    Data = null,
//                    ErrorData = null,
//                    Status = false
//                }); ;
//        }

        [HttpPost("RefreshToken")]
        public async Task<IActionResult> RefreshToken(RefreshTokenDto refreshTokenDto) {
            IEnumerable<KeyValuePair<string, string>> keyValuePairs = new Dictionary<string, string> {
                            {"grant_type","refresh_token" },{"client_id","Authentication"},{"client_secret","clientsecret"},{"scope","api.sample offline_access"},{"refresh_token",refreshTokenDto.RefreshToken}
                             };
            var domin = ContextHelper.GetDomin();
            AccesToken accesToken = await HttpClientHelper.PostFormUrlEncoded<AccesToken>($"{domin.AbsoluteUri}connect/token", keyValuePairs);

            if (!string.IsNullOrWhiteSpace(accesToken.access_token)) {
                return Ok(new ReturnDto() {
                    Data = accesToken,
                    ErrorData = null,
                    Status = true
                });
            }

            return Ok(new ReturnDto() {
                Data = null,
                ErrorData = null,
                Status = false
            }); ;

        }

        #endregion

        #region ManexAuthorize Attribute api

        [HttpPost("Authorize")]
        public IActionResult Authorize(AuthorizeDto authorizeDto) {
            long userId = GetUserIdFromAuthToken(authorizeDto.token);
            if (userId == default(long)) {
                return Ok(false);
            }
            var roles = _applicationRoleManager.GetRolesForUser(userId).Select(x => x.Name.ToUpper()).ToList();

            if (roles.Intersect(authorizeDto.roles).ToList().Any()) {
                return Ok(true);
            }
            return Ok(false);
        }

        #endregion

        #region Private

        [NonAction]
        private async Task<ReturnDto> Auth(VerifyEnum authority, AuthorityModel model) {

            ReturnDto ret;
            var authorities = _issuers["owner"].Authorities;
            string token = model.token;

            if (string.IsNullOrWhiteSpace(token)) {
                token = JwtHelper.GenerateToken(new Claim[] { }, _timeout * 3);
            }

            var principle = JwtHelper.GetClaimsPrincipal(token);

            if (principle?.Identity is ClaimsIdentity claimsIdentity && claimsIdentity.IsAuthenticated) {
                try {
//                    var claimsIdentity = principle.Identity as ClaimsIdentity;
                    var verifyResult = _issuers["owner"].Verify(authority, claimsIdentity.Claims.ToArray(), model.payload);

                    ret = await ResultFactory(authority, verifyResult);
                    return ret;

                } catch (Exception exc) {
                    ret = ExceptionReturn(exc);
                    return ret;
                }
            }
            return TokenNotValid();
        }

        [NonAction]
        private ReturnDto TokenNotValid() {
            List<ErrorDto> errorData = new List<ErrorDto>();
            errorData.Add(new ErrorDto() {
                Description = ErrorKey.ExpireToken,
                Key = nameof(ErrorKey.ExpireToken)
            });
            return new ReturnDto() {
                Data = null,
                ErrorData = errorData,
                Status = false
            };
        }

        private IActionResult RefreshTokenAuthNotVaild() {
            List<ErrorDto> errorData = new List<ErrorDto>();
            errorData.Add(new ErrorDto() {
                Description = ErrorKey.AuthroizeFaild,
                Key = nameof(ErrorKey.AuthroizeFaild)
            });

            return Ok(new ReturnDto() {
                Data = null,
                ErrorData = errorData,
                Status = false
            });
        }


        private async Task<ReturnDto> ResultFactory(VerifyEnum authority, IssuerVerifyResult verifyResult) {
            ReturnDto ret = new ReturnDto();
            switch (authority) {
                case VerifyEnum.account:
                case VerifyEnum.refreshToken:
                    ret = AccountResult(verifyResult);
                    break;
                case VerifyEnum.otp:
                case VerifyEnum.login:
                    ret = await OtpAndUserResult(verifyResult);
                    break;
            }
            return ret;
        }

        private static async Task<ReturnDto> OtpAndUserResult(IssuerVerifyResult verifyResult) {
            IEnumerable<KeyValuePair<string, string>> keyValuePairs = new Dictionary<string, string> {
                            {"grant_type","authentication" },{"client_id","Authentication"},{"client_secret","clientsecret"},{"scope","api.sample offline_access"},{"auth_token",verifyResult.Token}
                             };
            var domin = ContextHelper.GetDomin();
            AccesToken accesToken = await HttpClientHelper.PostFormUrlEncoded<AccesToken>($"{domin.AbsoluteUri}connect/token", keyValuePairs);
//            accesToken.auth_token = StringCipher.Encrypt(verifyResult.Token);

            return new ReturnDto() {
                Data = accesToken,
                ErrorData = null,
                Status = true
            };
        }

        private ReturnDto AccountResult(IssuerVerifyResult verifyResult) {
            return new ReturnDto() {
                Data = new { verify_token = verifyResult.Token },
                ErrorData = null,
                Status = true
            };
        }

        private static ReturnDto ExceptionReturn(Exception exc) {
            ReturnDto ret;
            var key = exc.Data.Keys.Cast<Gp_Error>().FirstOrDefault();
            List<ErrorDto> errorData = new List<ErrorDto>();

           
                switch (key) {
                    case Gp_Error.IdentityResultFaild:
                        if (exc.Data.Contains(key)) {

                            var statusMessage = exc.Data[key] as List<IdentityError>;

                            if (statusMessage != null)
                                foreach (var item in statusMessage) {
                                    errorData.Add(new ErrorDto() {Description = item.Description, Key = item.Code});
                                }
                        }

                        break;
                    case Gp_Error.Unknown:
                    default:
                        errorData.Add(new ErrorDto() {Description = exc.Message, Key = nameof(ErrorKey.Unknown)});

                        break;
                }
            

            @ret = new ReturnDto() {
                Data = null,
                ErrorData = errorData,
                Status = false
            };
            return ret;
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

        private IActionResult FaildAccessToken() {
            List<ErrorDto> errorData = new List<ErrorDto>();

            errorData.Add(new ErrorDto() {
                Description = ErrorKey.FaildAccessToken,
                Key = nameof(ErrorKey.FaildAccessToken)
            });

            return Ok(new ReturnDto() {
                Data = null,
                ErrorData = errorData,
                Status = false
            });
        }

        private IActionResult RefreshTokenResultFaild(IdentityResult result) {
            List<ErrorDto> errorDto = new List<ErrorDto>();
            foreach (var item in result.Errors.ToList()) {
                errorDto.Add(new ErrorDto() {
                    Description = item.Description,
                    Key = item.Code
                });
            }

            return Ok(new ReturnDto() {
                Data = null,
                ErrorData = errorDto,
                Status = false
            });
        }



        #endregion
    }

}