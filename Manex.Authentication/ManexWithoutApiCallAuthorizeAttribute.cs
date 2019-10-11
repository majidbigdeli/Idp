using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;

[AttributeUsage(AttributeTargets.Class | AttributeTargets.Method, AllowMultiple = true, Inherited = true)]
public class ManexWithoutApiCallAuthorizeAttribute : AuthorizeAttribute, IAuthorizationFilter {

    private readonly List<string> _roles;

    public ManexWithoutApiCallAuthorizeAttribute() {

    }

    public ManexWithoutApiCallAuthorizeAttribute(string[] roles) {
        _roles = new List<string>();
        foreach (var item in roles) {
            _roles.Add(item.ToUpper());
        }
    }

    public void OnAuthorization(AuthorizationFilterContext context) {
        var user = context.HttpContext.User;

        if (!user.Identity.IsAuthenticated) {
            return;
        }

        if (_roles?.Count > 0) {

            var isAuthorized = false;

            var roles = (from p in context.HttpContext.User.Claims where p.Type == ClaimTypes.Role select p.Value.ToUpper()).ToList();

            if (!roles.Except(_roles).Any()) {
                isAuthorized = true;
            }

            if (!isAuthorized) {
                context.Result = new StatusCodeResult((int)System.Net.HttpStatusCode.Forbidden);
                return;
            }

        }

    }
}
