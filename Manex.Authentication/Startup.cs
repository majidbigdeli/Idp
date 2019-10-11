using DNTCommon.Web.Core;
using IdentityServer4.Models;
using Manex.Authentication.Context;
using Manex.Authentication.Identity.Settings;
using Manex.Authentication.Services.Identity;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Tokens;
using Swashbuckle.AspNetCore.Swagger;
using System;
using System.Collections.Generic;
using System.Security.Cryptography;

namespace Manex.Authentication {


    public class Startup {

        public Startup(IConfiguration configuration) {
            Configuration = configuration;
        }

        public IConfiguration Configuration { get; }

        public void ConfigureServices(IServiceCollection services) {
            services.Configure<SiteSettings>(options => Configuration.Bind(options));

            // Adds all of the ASP.NET Core Identity related services and configurations at once.
            services.AddCustomIdentityServices();


            var siteSettings = services.GetSiteSettings();

            // It's added to access services from the dbcontext, remove it if you are using the
            // normal `AddDbContext` and normal constructor dependency injection.
            services.AddRequiredEfInternalServices(siteSettings);


            services.AddAuthentication(o => {
                o.DefaultAuthenticateScheme = "Bearer";
                o.DefaultScheme = "Bearer";
                o.DefaultChallengeScheme = "Bearer";
            }).AddJwtBearer("Bearer", options => {
                options.Authority = siteSettings.Authority; //Configuration.GetSection("Authority").Value;
                options.RequireHttpsMetadata = false;
                options.Audience = "api.sample";
            });

            services.AddCors(options => {
                options.AddPolicy("default", policy => {
                    policy.AllowAnyOrigin()
                    .AllowAnyHeader()
                    .AllowAnyMethod();
                });
            });


            services.AddIdentityServer(options => {
                options.Events.RaiseErrorEvents = true;
                options.Events.RaiseInformationEvents = true;
                options.Events.RaiseFailureEvents = true;
                options.Events.RaiseSuccessEvents = true;
            })
        //.AddDeveloperSigningCredential()
        .AddInMemoryIdentityResources(GetIdentityResources())
        .AddInMemoryApiResources(GetApiResources())
        .AddInMemoryClients(GetClients(siteSettings))
        .AddExtensionGrantValidator<AuthenticationGrant>()
        .AddProfileService<AspNetIdentityProfileService>()
        .AddSigningCredential(new SigningCredentials(RsaSecurityKeyManager.getInstance(), SecurityAlgorithms.RsaSha256));

            services.AddDbContextPool<ApplicationDbContext>((serviceProvider, optionsBuilder) => {
                optionsBuilder.SetDbContextOptions(siteSettings);

                // It's added to access services from the dbcontext, remove it if you are using the
                // normal `AddDbContext` and normal constructor dependency injection.
                optionsBuilder.UseInternalServiceProvider(serviceProvider);
            });

            services.AddMvc(options => {
                options.UseYeKeModelBinder();
                options.AllowEmptyInputInBodyModelBinding = true;

                // options.Filters.Add(new NoBrowserCacheAttribute());
            }).AddJsonOptions(jsonOptions => {
                jsonOptions.SerializerSettings.NullValueHandling = Newtonsoft.Json.NullValueHandling.Ignore;
            })
                    .AddControllersAsServices()
                    .SetCompatibilityVersion(CompatibilityVersion.Version_2_2);


            services.AddSwaggerGen(x => {
                x.SwaggerDoc("v1", new Info() { Title = "Manex Api", Version = "v1" });

                x.DocInclusionPredicate((docName, description) => true);
            });


            services.AddDNTCommonWeb();
            services.AddCloudscribePagination();
        }

        public void Configure(IApplicationBuilder app, IHostingEnvironment env) {
            if (!env.IsDevelopment()) {
                app.UseHsts();
            }

            app.UseCors("default");
            app.UseIdentityServer();
            app.UseAuthentication();


            // app.UseNoBrowserCache();

            app.UseSwagger();

            app.UseSwaggerUI(c => {
                c.SwaggerEndpoint("/swagger/v1/swagger.json", "Manex API V1");

                //                c.RoutePrefix = string.Empty;
            });

            app.UseMvc(routes => {
                routes.MapRoute(
                                name: "areas",
                                template: "{area:exists}/{controller=Account}/{action=Index}/{id?}");

                routes.MapRoute(
                                name: "default",
                                template: "{controller=Home}/{action=Index}/{id?}");
            });
        }


        public static IEnumerable<IdentityResource> GetIdentityResources() {
            return new List<IdentityResource>
            {
        new IdentityResources.OpenId()
    };
        }

        public static IEnumerable<ApiResource> GetApiResources() {
            return new List<ApiResource>
            {
                new ApiResource("api.sample", "Sample API")
    };
        }

        public static IEnumerable<Client> GetClients(SiteSettings siteSettings) {
            return new List<Client>
            {
          new Client
                                    {
                                        ClientId = "Authentication",
                                        ClientSecrets =
                                        {
                                            new Secret("clientsecret".Sha256())
                                        },
                                        AllowedGrantTypes = { "authentication" },
                                        AllowedScopes =
                                        {
                                            "api.sample"
                                        },
                                        AllowOfflineAccess = true,
                                        AccessTokenLifetime = siteSettings.Expire.AccessTokenLifetime,
                                        UpdateAccessTokenClaimsOnRefresh = true,
                                        RefreshTokenUsage = TokenUsage.OneTimeOnly,
                                        RefreshTokenExpiration = TokenExpiration.Sliding,
                                        AbsoluteRefreshTokenLifetime = siteSettings.Expire.AbsoluteRefreshTokenLifetime,
                                        SlidingRefreshTokenLifetime =  siteSettings.Expire.AbsoluteRefreshTokenLifetime/2



        }
    };
        }



    }



}