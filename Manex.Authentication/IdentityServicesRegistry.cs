using Manex.Authentication.Contracts.Identity;
using Manex.Authentication.GuardToolkit;
using Manex.Authentication.Identity.Settings;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using System;

namespace Manex.Authentication
{
    public static class IdentityServicesRegistry
    {
        /// <summary>
        /// Adds all of the ASP.NET Core Identity related services and configurations at once.
        /// </summary>
        public static void AddCustomIdentityServices(this IServiceCollection services)
        {
            var siteSettings = GetSiteSettings(services);
            services.AddIdentityOptions(siteSettings);
            services.AddCustomServices();
            services.AddCustomTicketStore(siteSettings);
            services.AddDynamicPermissions();
            services.AddCustomDataProtection(siteSettings);
        }

        /// <summary>
        /// Creates and seeds the database.
        /// </summary>
        public static void InitializeDb(this IServiceProvider serviceProvider)
        {
            var scopeFactory = serviceProvider.GetRequiredService<IServiceScopeFactory>();
            using (var scope = scopeFactory.CreateScope())
            {
                var identityDbInitialize = scope.ServiceProvider.GetService<IIdentityDbInitializer>();
                identityDbInitialize.Initialize();
                identityDbInitialize.SeedData();
            }
        }

        public static SiteSettings GetSiteSettings(this IServiceCollection services)
        {
            var provider = services.BuildServiceProvider();
            var siteSettingsOptions = provider.GetService<IOptionsSnapshot<SiteSettings>>();
            siteSettingsOptions.CheckArgumentIsNull(nameof(siteSettingsOptions));
            var siteSettings = siteSettingsOptions.Value;
            siteSettings.CheckArgumentIsNull(nameof(siteSettings));
            return siteSettings;
        }
    }



}
