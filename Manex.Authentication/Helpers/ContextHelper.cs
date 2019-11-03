using Microsoft.AspNetCore.Http;
using System;

using Microsoft.AspNetCore.Http.Extensions;

namespace WebIddentityServer4.Helpers {
    public static class ContextHelper {

        public static Uri GetAbsoluteUri() {

            var _contextAccessor = new HttpContextAccessor();
            var request = _contextAccessor.HttpContext.Request;
            UriBuilder uriBuilder = new UriBuilder();
            uriBuilder.Scheme = request.Scheme;
            uriBuilder.Host = request.Host.Host;
            uriBuilder.Port = request.Host.Port.Value;
            uriBuilder.Path = request.Path.ToString();
            uriBuilder.Query = request.QueryString.ToString();
            return uriBuilder.Uri;
        }

        public static Uri GetDomin(IHttpContextAccessor httpContextAccessor) {
            Console.WriteLine("httpContextAccessor = " + httpContextAccessor);
            var _contextAccessor = httpContextAccessor ?? new HttpContextAccessor();
            var request = _contextAccessor.HttpContext.Request;
            Console.WriteLine("Reuest: " + request.GetDisplayUrl());
            var uri = new Uri(request.GetDisplayUrl());
            UriBuilder uriBuilder = new UriBuilder();
            uriBuilder.Host = uri.Host;
            uriBuilder.Port = uri.Port;
            uriBuilder.Scheme = uri.Scheme;
            Console.WriteLine("URI = " + uriBuilder.Uri);
            return uriBuilder.Uri;



        }

    }


}
