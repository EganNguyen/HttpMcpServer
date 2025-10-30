using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using DotNetEnv;
using McpServer;
using McpServer.DbContext;
using Microsoft.EntityFrameworkCore;

var builder = WebApplication.CreateBuilder(args);

Env.Load("../.env");

builder.Configuration.AddEnvironmentVariables();
builder.Services.AddMcpServer()
    .WithHttpTransport()
    .WithToolsFromAssembly();
builder.WebHost.ConfigureKestrel(options =>
{
    options.ListenLocalhost(builder.Configuration.GetValue<int>("HOST_PORT"));
}); 
builder.Services.AddDbContext<ApplicationDbContext>(opt => opt.UseNpgsql(builder.Configuration.GetConnectionString("DefaultConnection")));

builder.Services.AddHttpClient<IEpicClient, EpicClient>();
builder.Services.AddHttpClient<IOdooClient, OdooClient>();  
builder.Services.AddScoped<IPostgresService, PostgresService>();



var app = builder.Build();

// minimal api for EPIC verify access token
var keyId = builder.Configuration.GetValue<string>("EPIC:KID");
string home = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
string pemPath = Path.Combine(home, "publickey509.pem");
string pem = File.ReadAllText(pemPath);
var cert = X509Certificate2.CreateFromPem(pem);

// Extract RSA public key
var rsa = cert.GetRSAPublicKey();

// Export modulus/exponent for JWK
var parameters = rsa.ExportParameters(false);

string Base64UrlEncode(byte[] input) =>
    Convert.ToBase64String(input)
        .TrimEnd('=')
        .Replace('+', '-')
        .Replace('/', '_');

var jwk = new
{
    kty = "RSA",
    kid = keyId,
    use = "sig",
    alg = "RS384", // must match your signing algorithm
    n = Base64UrlEncode(parameters.Modulus),
    e = Base64UrlEncode(parameters.Exponent)
};
app.MapGet("/.well-known/jwks.json", () => new { keys = new[] { jwk } });
app.MapMcp();
app.Run();
