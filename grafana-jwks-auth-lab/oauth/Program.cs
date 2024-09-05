using System.IdentityModel.Tokens.Jwt;
using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.IdentityModel.Tokens;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddCors(options =>
{
    options.AddPolicy("AllowAll",
        policy =>
        {
            policy.AllowAnyOrigin()
                  .AllowAnyHeader()
                  .AllowAnyMethod();
        });
});

var app = builder.Build();

var rsa = RSA.Create();
var folderPath = Path.Combine(AppContext.BaseDirectory, "secrets");
string jwksFilePath = Path.Combine(folderPath, "jwks.json");
string privateKeyFilePath = Path.Combine(folderPath, "private.key");
string publicKeyFilePath = Path.Combine(folderPath, "public.pem");

app.MapGet("/jwks", async () =>
{
    if (!Directory.Exists(folderPath))
        Directory.CreateDirectory(folderPath);

    if (!File.Exists(jwksFilePath))
    {
        var key = new RsaSecurityKey(rsa) { KeyId = Guid.NewGuid().ToString() };

        var jwk = new JsonWebKey
        {
            Kty = "RSA",
            Kid = key.KeyId,
            N = Base64UrlEncoder.Encode(key.Rsa.ExportParameters(false).Modulus),
            E = Base64UrlEncoder.Encode(key.Rsa.ExportParameters(false).Exponent),
            Alg = "RS256",
            Use = "sig"
        };

        var jwks = new
        {
            keys = new[] { jwk }
        };

        var json = JsonSerializer.Serialize(jwks, new JsonSerializerOptions { WriteIndented = true });
        await File.WriteAllTextAsync(jwksFilePath, json);

        var privateKey = Convert.ToBase64String(rsa.ExportRSAPrivateKey());
        await File.WriteAllTextAsync(privateKeyFilePath, privateKey);

        var publicKey = Convert.ToBase64String(rsa.ExportRSAPublicKey());
        await File.WriteAllTextAsync(publicKeyFilePath, publicKey);
    }

    return Results.File(jwksFilePath, "application/json");
});

app.MapGet("/auth", async () =>
{
    if (File.Exists(privateKeyFilePath) && File.Exists(jwksFilePath))
    {
        var jwksContent = await File.ReadAllTextAsync(jwksFilePath);
        var jwks = JsonSerializer.Deserialize<JsonWebKeySet>(jwksContent);
        var kid = jwks?.Keys.FirstOrDefault()?.Kid;

        if (kid == null)
        {
            return Results.BadRequest("Unable to find KeyId (kid) in JWKS.");
        }

        var privateKeyBase64 = await File.ReadAllTextAsync(privateKeyFilePath);
        var privateKeyBytes = Convert.FromBase64String(privateKeyBase64);

        rsa.ImportRSAPrivateKey(privateKeyBytes, out _);

        var key = new RsaSecurityKey(rsa)
        {
            KeyId = kid
        };

        var signingCredentials = new SigningCredentials(key, SecurityAlgorithms.RsaSha256);

        var tokenDescriptor = new SecurityTokenDescriptor
        {
            Subject = new System.Security.Claims.ClaimsIdentity(new[]
            {
                new System.Security.Claims.Claim("sub", "admin"),
                new System.Security.Claims.Claim("role", "Admin")
            }),
            Expires = DateTime.UtcNow.AddHours(1),
            SigningCredentials = signingCredentials
        };

        var tokenHandler = new JwtSecurityTokenHandler();
        var token = tokenHandler.CreateToken(tokenDescriptor);
        var tokenString = tokenHandler.WriteToken(token);

        return Results.Json(new { token = tokenString });
    }

    return Results.BadRequest();
});

app.UseCors("AllowAll");

app.Run();
