using EXJWT.Model.Context;
using EXJWT.Model.Services.Repository;
using EXJWT.Model.Services.Validator;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.HttpsPolicy;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi.Models;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace EXJWT
{
    public class Startup
    {
        public Startup(IConfiguration configuration)
        {
            Configuration = configuration;
        }

        public IConfiguration Configuration { get; }

        // This method gets called by the runtime. Use this method to add services to the container.
        public void ConfigureServices(IServiceCollection services)
        {

            services.AddControllers();
            services.AddScoped<UserTokenRepository, UserTokenRepository>();
            services.AddScoped<UserRepository, UserRepository>();
            services.AddScoped<ITokenValidator, TokenValidator>();

            services.AddAuthentication(p => {
                p.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
                p.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
                p.DefaultSignInScheme = JwtBearerDefaults.AuthenticationScheme;
            }).AddJwtBearer(configureOptions =>
            {
                configureOptions.TokenValidationParameters = new TokenValidationParameters()
                {
                    ValidIssuer = Configuration["JWtConfig:issuer"],
                    ValidAudience = Configuration["JWtConfig:audience"],
                    IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(Configuration["JWtConfig:Key"])),
                    ValidateIssuerSigningKey = true,
                    ValidateLifetime = true,
                };
                configureOptions.SaveToken = true; // HttpContext.GetTokenAsunc();
                configureOptions.Events = new JwtBearerEvents
                {
                    OnAuthenticationFailed = context =>
                    {
                        //log 
                        //........
                        return Task.CompletedTask;
                    },
                    OnTokenValidated = context =>
                    {
                        var TokenValidate = context.HttpContext.RequestServices.GetRequiredService<ITokenValidator>();
                        return TokenValidate.Execute(context);
                    },
                    OnChallenge = context =>
                    {
                        return Task.CompletedTask;

                    },
                    OnMessageReceived = context =>
                    {
                        return Task.CompletedTask;

                    },
                    OnForbidden = context =>
                    {
                        return Task.CompletedTask;

                    }
                };

            });
            services.AddSwaggerGen(c =>
            {
                c.SwaggerDoc("v1", new OpenApiInfo { Title = "EXJWT", Version = "v1" });


                //LogOut
                var security = new OpenApiSecurityScheme
                {
                    Name = "JWT Auth",
                    Description = "توکن خود را وارد کنید- دقت کنید فقط توکن را وارد کنید",
                    In = ParameterLocation.Header,
                    Type = SecuritySchemeType.Http,
                    Scheme = "bearer",
                    BearerFormat = "JWT",
                    Reference = new OpenApiReference
                    {
                        Id = JwtBearerDefaults.AuthenticationScheme,
                        Type = ReferenceType.SecurityScheme
                    }
                };
                c.AddSecurityDefinition(security.Reference.Id, security);
                c.AddSecurityRequirement(new OpenApiSecurityRequirement
                {
                    { security , new string[]{ } }
                });
            });

            string ConnectionString = @"data source =.; initial catalog = JWTDb;  integrated security = true  ";
            services.AddEntityFrameworkSqlServer().AddDbContext<DataBaseContext>(option => option.UseSqlServer(ConnectionString));
        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
        {
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
                app.UseSwagger();
                app.UseSwaggerUI(c => c.SwaggerEndpoint("/swagger/v1/swagger.json", "EXJWT v1"));
            }

            app.UseHttpsRedirection();

            app.UseRouting();

            app.UseAuthentication();
            app.UseAuthorization();

            app.UseEndpoints(endpoints =>
            {
                endpoints.MapControllers();
            });
        }
    }
}
