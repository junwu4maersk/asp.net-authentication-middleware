
using System.Security.Claims;
using System.Text;
using System.Text.Encodings.Web;
using AuthenticationMiddleware.SampleWebAPI.Middlewares;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
namespace AuthenticationMiddleware.SampleWebAPI.Auth;

public class BasicAuthenticationHandler : AuthenticationHandler<AuthenticationSchemeOptions>
{
    private readonly IConfiguration _configuration;

    public BasicAuthenticationHandler(
        IOptionsMonitor<AuthenticationSchemeOptions> options,
        ILoggerFactory logger,
        UrlEncoder encoder,
        ISystemClock clock,
        IConfiguration configuration)
        : base(options, logger, encoder, clock)
    {
        _configuration = configuration;
    }

    protected override Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        if (!Request.Headers.ContainsKey("Authorization"))
        {
            return Task.FromResult(AuthenticateResult.Fail("Missing Authorization Header"));
        }

        var authHeader = Request.Headers["Authorization"].ToString();
        if (!authHeader.StartsWith("Basic ", StringComparison.OrdinalIgnoreCase))
        {
            return Task.FromResult(AuthenticateResult.Fail("Invalid Authorization Header"));
        }

        var encodedCredentials = authHeader.Substring("Basic ".Length).Trim();
        string decodedCredentials;
        try
        {
            decodedCredentials = Encoding.UTF8.GetString(Convert.FromBase64String(encodedCredentials));
        }
        catch
        {
            return Task.FromResult(AuthenticateResult.Fail("Invalid Base64 Encoding"));
        }

        var credentials = decodedCredentials.Split(':', 2);
        if (credentials.Length != 2)
        {
            return Task.FromResult(AuthenticateResult.Fail("Invalid Credentials Format"));
        }

        var username = credentials[0];
        var password = credentials[1];

        
        var validUsername = _configuration["BasicAuth:Username"];
        var validPassword = _configuration["BasicAuth:Password"];

        if (username != validUsername || password != validPassword)
        {
            return Task.FromResult(AuthenticateResult.Fail("Invalid Username or Password"));
        }

        
        var claims = new[] { new Claim(ClaimTypes.Name, username) };
        var identity = new ClaimsIdentity(claims, Scheme.Name);
        var principal = new ClaimsPrincipal(identity);
        var ticket = new AuthenticationTicket(principal, Scheme.Name);

        return Task.FromResult(AuthenticateResult.Success(ticket));
    }

    protected override Task HandleChallengeAsync(AuthenticationProperties properties)
    {
        Response.StatusCode = 401;
        Response.Headers["WWW-Authenticate"] = $"Basic realm=\"{Options.ClaimsIssuer}\"";
        return base.HandleChallengeAsync(properties);
    }
}
public static class BasicAuthenticationHandlerExtensions
{
    public static IServiceCollection UseBasicAuth(this IServiceCollection services)
    {
        services.AddAuthentication(options =>
        {
            options.DefaultAuthenticateScheme = null;
            options.DefaultChallengeScheme = null;
        }).AddScheme<AuthenticationSchemeOptions, BasicAuthenticationHandler>("Basic", options => { });
        return services;
    }
}