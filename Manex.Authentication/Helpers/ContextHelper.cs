using Microsoft.AspNetCore.Http;
using System;

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

        public static Uri GetDomin() {
            var _contextAccessor = new HttpContextAccessor();
            var request = _contextAccessor.HttpContext.Request;
            UriBuilder uriBuilder = new UriBuilder();
            uriBuilder.Host = request.Host.Host;
            uriBuilder.Port = request.Host.Port.Value;

            return uriBuilder.Uri;



        }

    }


}
