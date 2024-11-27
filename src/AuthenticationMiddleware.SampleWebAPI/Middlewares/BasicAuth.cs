using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using System.Net.Http.Headers;
using System.Text;
using System.Threading.Tasks;
namespace AuthenticationMiddleware.SampleWebAPI.Middlewares;

public class BasicAuthMiddleware
{
    private readonly RequestDelegate _next;
    private readonly string _username;
    private readonly string _password;

    public BasicAuthMiddleware(RequestDelegate next, IConfiguration configuration)
    {
        _next = next;
        _username = configuration["BasicAuth:Username"];
        _password = configuration["BasicAuth:Password"];
    }

    public async Task InvokeAsync(HttpContext context)
    {
        if (!context.Request.Headers.ContainsKey("Authorization"))
        {
            context.Response.StatusCode = 401;
            context.Response.Headers.Add("WWW-Authenticate", "Basic realm=\"dotnetcore\"");
            await context.Response.WriteAsync("Unauthorized");
            return;
        }

        var authHeader = AuthenticationHeaderValue.Parse(context.Request.Headers["Authorization"]);
        var credentialBytes = Convert.FromBase64String(authHeader.Parameter);
        var credentials = Encoding.UTF8.GetString(credentialBytes).Split(':');
        var username = credentials[0];
        var password = credentials[1];

        if (username != _username || password != _password)
        {
            context.Response.StatusCode = 401;
            context.Response.Headers.Add("WWW-Authenticate", "Basic realm=\"dotnetcore\"");
            await context.Response.WriteAsync("Unauthorized");
            return;
        }

        await _next(context);
    }
}
public static class BasicAuthMiddlewareExtensions
{
    public static IApplicationBuilder UseBasicAuth(this IApplicationBuilder builder)
    {
        return builder.UseMiddleware<BasicAuthMiddleware>();
    }
}