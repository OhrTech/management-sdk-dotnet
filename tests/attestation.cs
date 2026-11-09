#:project ../src/OhrTech.Management/OhrTech.Management.csproj
// Checks DeviceAttestationVerifier, AttestationToken and AttestationStatusList on a real attestation from an
// OhrTech device: the Device SDK sample's device checks write it (check "attestation", file checks-attestation.json,
// plus "challenge": the challenge it was given).
//   dotnet run tests/attestation.cs -- checks-attestation.json [--online]
// --online also fetches and opens the live status list (https://api.ohrtech.net/v1/attestations/status).
using System.Buffers.Text;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using OhrTech.Management.Attestation;

if (args.Length < 1) throw new ArgumentException("usage: dotnet run tests/attestation.cs -- checks-attestation.json [--online]");
using var doc = JsonDocument.Parse(File.ReadAllText(args[0]));
var v = doc.RootElement;
var challenge = Encoding.UTF8.GetBytes(v.GetProperty("challenge").GetString()!);
var package = v.GetProperty("session").GetProperty("package").GetString()!;  // the app that made it
var verifier = new DeviceAttestationVerifier(new DeviceAttestationPolicy { PackageName = package, MinOsPatchLevel = 202610 });

var ec = verifier.Verify(v.GetProperty("ec").GetRawText(), challenge);
Check(ec.Accepted, $"EC accepted ({ec.Reason}; {string.Join(", ", ec.Problems)})");
Check(ec.DeviceId?.StartsWith("dev_") == true && ec.PackageName == package && ec.Suite == AttestationSuite.Ec, $"EC names {ec.DeviceId}, {ec.PackageName}");
Check(ec.VerifiedBootKeySha256 == OhrTechAttestation.VerifiedBootKeySha256 && ec.DeviceLocked == true, "EC: OhrTech boot, locked");
Check(ec.MlDsa65PublicKey == null && ec.EcPublicKey != null, "EC: one key");

var hy = verifier.Verify(v.GetProperty("hybrid").GetRawText(), challenge);
Check(hy.Accepted && hy.Suite == AttestationSuite.EcMlDsa65 && hy.MlDsa65PublicKey?.Length > 1900, $"EC + ML-DSA-65 accepted ({hy.Reason})");
Check(hy.DeviceId == ec.DeviceId, "both suites: the same unit");

Check(!verifier.Verify(v.GetProperty("ec").GetRawText(), "other"u8.ToArray()).Valid, "wrong challenge fails");
var other = new DeviceAttestationVerifier(new DeviceAttestationPolicy { PackageName = "com.other" }).Verify(v.GetProperty("ec").GetRawText(), challenge);
Check(other.Valid && !other.Accepted && other.Problems.Single() == "the key is not com.other's", "another package is a problem");

// Tokens: the EC token was made with the EC suite's key, the hybrid one with the hybrid suite's keys.
var tokenEc = v.GetProperty("tokenEc").GetString()!;
var tokenHy = v.GetProperty("tokenHybrid").GetString()!;
var aud = "https://example.test";
DateTimeOffset IssuedAt(string t)
{
    using var p = JsonDocument.Parse(Base64Url.DecodeFromChars(t.Split('.')[1]));
    return DateTimeOffset.FromUnixTimeSeconds(p.RootElement.GetProperty("iat").GetInt64());
}
var atEc = IssuedAt(tokenEc).AddSeconds(5);
var atHy = IssuedAt(tokenHy).AddSeconds(5);
Check(AttestationToken.Verify(tokenEc, aud, ec.EcPublicKey!, at: atEc).Audience == aud, "EC token verifies");
Check(AttestationToken.Verify(tokenHy, aud, hy.EcPublicKey!, hy.MlDsa65PublicKey, at: atHy).Audience == aud, "hybrid token verifies");
Fails(() => AttestationToken.Verify(tokenEc, "https://elsewhere.test", ec.EcPublicKey!, at: atEc), "another audience");
Fails(() => AttestationToken.Verify(tokenEc, aud, ec.EcPublicKey!, at: atEc.AddHours(1)), "an expired token");
Fails(() => AttestationToken.Verify(tokenEc, aud, hy.EcPublicKey!, at: atEc), "another device's key");
Fails(() => AttestationToken.Verify(tokenHy, aud, hy.EcPublicKey!, at: atHy), "a hybrid token where an EC one is expected");
Fails(() => AttestationToken.Verify(tokenEc, aud, hy.EcPublicKey!, hy.MlDsa65PublicKey, at: atEc), "an EC token where a hybrid one is pinned");
var parts = tokenHy.Split('.');
var sig = Base64Url.DecodeFromChars(parts[3]);
sig[100] ^= 1;
Fails(() => AttestationToken.Verify(string.Join('.', parts[0], parts[1], parts[2], Base64Url.EncodeToString(sig)), aud, hy.EcPublicKey!, hy.MlDsa65PublicKey, at: atHy),
    "a broken ML-DSA-65 signature");

if (args.Contains("--online"))
{
    using var http = new HttpClient();
    var status = await AttestationStatusList.FetchAsync(http);
    Check(status.ExpiresAt > DateTimeOffset.UtcNow, $"live status list opens ({status.Entries.Count} revoked, until {status.ExpiresAt:u})");
    var withStatus = verifier.Verify(v.GetProperty("hybrid").GetRawText(), challenge, status);
    Check(withStatus.Accepted == !hy.UnitCertificateSerials.Any(status.Entries.ContainsKey), "the verdict follows the status list");
    var jws = await http.GetStringAsync(AttestationStatusList.DefaultUrl);
    var p = jws.Split('.');
    Fails(() => AttestationStatusList.Open(p[0] + "." + Base64Url.EncodeToString("{\"iat\":1,\"exp\":9999999999,\"entries\":{}}"u8) + "." + p[2]),
        "a status list with another payload");
}

Console.WriteLine("all attestation checks passed");

static void Check(bool ok, string what)
{
    if (!ok) throw new Exception("FAILED: " + what);
    Console.WriteLine("ok   " + what);
}

static void Fails(Action a, string what)
{
    try
    {
        a();
    }
    catch (CryptographicException e)
    {
        Console.WriteLine($"ok   refused {what}: {e.Message}");
        return;
    }
    throw new Exception("FAILED: accepted " + what);
}
