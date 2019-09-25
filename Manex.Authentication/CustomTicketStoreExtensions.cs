using Manex.Authentication.Services.Identity;
using Manex.Authentication.Context;
using Manex.Authentication.Identity.Settings;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.Extensions.DependencyInjection;

namespace Manex.Authentication
{
    public static class CustomTicketStoreExtensions
    {
        public static IServiceCollection AddCustomTicketStore(
            this IServiceCollection services, SiteSettings siteSettings)
        {
            // To manage large identity cookies
            var cookieOptions = siteSettings.CookieOptions;
            if (cookieOptions.UseDistributedCacheTicketStore && isActiveDatabaseSqlServer(siteSettings))
            {
                services.AddDistributedSqlServerCache(options =>
                {
                    var cacheOptions = cookieOptions.DistributedSqlServerCacheOptions;
                    var connectionString = string.IsNullOrWhiteSpace(cacheOptions.ConnectionString) ?
                            siteSettings.GetDbConnectionString() :
                            cacheOptions.ConnectionString;
                    options.ConnectionString = connectionString;
                    options.SchemaName = cacheOptions.SchemaName;
                    options.TableName = cacheOptions.TableName;
                });
                services.AddScoped<ITicketStore, DistributedCacheTicketStore>();
            }
            else
            {
                services.AddMemoryCache();
                services.AddScoped<ITicketStore, MemoryCacheTicketStore>();
            }

            return services;
        }

        private static bool isActiveDatabaseSqlServer(SiteSettings siteSettings)
        {
            return siteSettings.ActiveDatabase == ActiveDatabase.LocalDb
                   || siteSettings.ActiveDatabase == ActiveDatabase.SqlServer || siteSettings.ActiveDatabase == ActiveDatabase.Postgres;
        }
    }



}
