using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;
using Microsoft.Extensions.Configuration;
using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Text;


    [AttributeUsage(AttributeTargets.Class | AttributeTargets.Method, AllowMultiple = true, Inherited = true)]
    public class ManexAuthorizeAttribute : AuthorizeAttribute, IAuthorizationFilter {

        private readonly List<string> _roles;

        public ManexAuthorizeAttribute() {

        }

        public ManexAuthorizeAttribute(string[] roles) {
            _roles = new List<string>();
            foreach (var item in roles) {
                _roles.Add(item.ToUpper());
            }
        }

        public void OnAuthorization(AuthorizationFilterContext context) {
            var user = context.HttpContext.User;

            if (!user.Identity.IsAuthenticated) {
                // it isn't needed to set unauthorized result 
                // as the base class already requires the user to be authenticated
                // this also makes redirect to a login page work properly
                // context.Result = new UnauthorizedResult();
                return;
            }

            if (_roles?.Count > 0) {
                var authroize = context.HttpContext.Request.Headers["Authroize"].ToString();

                if (string.IsNullOrWhiteSpace(authroize)) {
                    context.Result = new StatusCodeResult((int)System.Net.HttpStatusCode.Forbidden);
                    return;
                }

                var configuration = context.HttpContext.RequestServices.GetService(typeof(IConfiguration)) as IConfiguration;

                var authority = configuration.GetSection("Authority").Value;

                var client = new HttpClient();

                var responseMessage = client.PostAsync($"{authority}/api/Authority/Authorize", new StringContent(JsonConvert.SerializeObject(new { roles = _roles, token = authroize }), Encoding.UTF8, "application/json")).Result;

                var isAuthorized = bool.Parse(responseMessage.Content.ReadAsStringAsync().Result);
                if (!isAuthorized) {
                    context.Result = new StatusCodeResult((int)System.Net.HttpStatusCode.Forbidden);
                    return;
                }

            }




        }
    }

