
using AuthenticationMiddleware.SampleWebAPI.Auth;
using AuthenticationMiddleware.SampleWebAPI.Middlewares;
using Microsoft.AspNetCore.Authentication;

namespace AuthenticationMiddleware.SampleWebAPI
{
    public class Program
    {
        public static void Main(string[] args)
        {
            var builder = WebApplication.CreateBuilder(args);

            // Add services to the container.

            builder.Services.AddControllers();
            // Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
            builder.Services.AddEndpointsApiExplorer();
            builder.Services.AddSwaggerGen();

            // option 1. use AuthenticationBuilder
            builder.Services.UseBasicAuth();

            var app = builder.Build();

            // Configure the HTTP request pipeline.
            if (app.Environment.IsDevelopment())
            {
                app.UseSwagger();
                app.UseSwaggerUI();
            }

            app.UseHttpsRedirection();

            app.UseAuthorization();
            app.UseAuthentication();

            // option 2. use middleware
            //app.UseBasicAuth();
            app.MapControllers();

            app.Run();
        }
    }
}
