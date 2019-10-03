using System;
using Manex.Authentication.Contracts.Identity;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using Newtonsoft.Json.Linq;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using Manex.Authentication.Entities.Identity;
using Microsoft.Extensions.Configuration;
using WebIddentityServer4.Authorities;
using WebIddentityServer4.Helpers;

namespace Manex.Authentication.Controllers
{

    public class AuthorityModel
    {
        public JObject payload { get; set; }
        public string token { get; set; }
    }


    [AllowAnonymous]
    [Produces("application/json")]
    [Route("api/[controller]")]
    public class AuthorityController : Controller
    {
        private readonly IApplicationUserManager _applicationUserManager;
        private Dictionary<string, AuthorityIssuer> _issuers;

        public AuthorityController(IApplicationUserManager applicationUserManager,
            IApplicationSignInManager applicationSignInManager,
            ILogger<AuthorityController> logger,IConfiguration configuration)
        {
            _applicationUserManager = applicationUserManager;

            _issuers = new Dictionary<string, AuthorityIssuer>()
            {
                {
                    "owner",
                    AuthorityIssuer.Create(new AuthenticationAuthority(), "identity")
                        .Register("account", new AccountAuthority(applicationUserManager))
                        .Register("otp", new OTPAuthority(logger,configuration))
                        .Register("login",new LoginAuthority(applicationUserManager,applicationSignInManager))
                }
            };
        }

        [HttpPost("Auth")]
        public IActionResult Auth([FromBody] AuthorityModel model)
        {

            return Auth("",model);
        }

        [HttpPost("Auth/{authority}")]
        public IActionResult Auth(string authority, [FromBody] AuthorityModel model)
        {
            if (model == null || model?.payload == null)
                return Unauthorized();
            var authorities = _issuers["owner"].Authorities;
            if (!authorities.Any())
                return Unauthorized();
            string token = model.token;
            if (string.IsNullOrWhiteSpace(authority))
            {
                authority = authorities.Keys.ToArray()[0];
            }
            if (string.IsNullOrWhiteSpace(token))
            {
                token = JwtHelper.GenerateToken(new Claim[] { }, 60);
            }
            if (string.IsNullOrWhiteSpace(token))
                return Unauthorized();
            var principle = JwtHelper.GetClaimsPrincipal(token);

            if (principle?.Identity?.IsAuthenticated == true)
            {
                try
                {
                    var claimsIdentity = principle.Identity as ClaimsIdentity;
                    var verifyResult = _issuers["owner"].Verify(authority, claimsIdentity.Claims.ToArray(), model.payload);
                    if (verifyResult.Authority == null)
                        return Ok(new { auth_token = verifyResult.Token });
                    return Ok(new { verify_token = verifyResult.Token, authority = verifyResult.Authority, parameters = verifyResult.Payload });
                }
                catch
                {
                    return Unauthorized();
                }
            }

            return Unauthorized();

        }


        [HttpGet("Register")]
        public async Task<IActionResult> Register()
        {
            try
            {

            
            var res = await _applicationUserManager.CreateAsync(new User()
            {
                FirstName = "alireza1",
                LastName = "kazem1",
                BirthDate = DateTimeOffset.Now,
                PhoneNumber = "9112252072",
                Email = "lrz.kazem1@yahoo.com",
                UserName = "9112252072",
                IsActive = true
            });
            return Ok(res);
            }
            catch (Exception e)
            {
                Console.WriteLine(e);
            }
            return Ok();
        }



    }
}