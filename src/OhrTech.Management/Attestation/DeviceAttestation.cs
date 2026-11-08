#if NET10_0_OR_GREATER
using System;
using System.Buffers.Text;
using System.Collections.Generic;
using System.Formats.Asn1;
using System.Linq;
using System.Net.Http;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace OhrTech.Management.Attestation;

/// <summary>
/// The attestation suites of the Device SDK's <c>OhrAttestation</c>: an EC P-256 key, or an EC key and an ML-DSA-65
/// key together (post-quantum), both attested, everything signed with both.
/// </summary>
public static class AttestationSuite
{
    public const string Ec = "ec";
    public const string EcMlDsa65 = "ec-mldsa65";
}

/// <summary>
/// OhrTech's attestation trust: the OhrTech Attestation Root, and the values its chains carry.
/// </summary>
public static class OhrTechAttestation
{
    /// <summary>The OhrTech Attestation Root (also at GET https://api.ohrtech.net/v1/attestations/root).</summary>
    public const string RootPem = """
        -----BEGIN CERTIFICATE-----
        MIIB6TCCAW+gAwIBAgIQV70j9cGPigqQcXS7iB/zEjAKBggqhkjOPQQDAzA1MRAw
        DgYDVQQKDAdPaHJUZWNoMSEwHwYDVQQDDBhPaHJUZWNoIEF0dGVzdGF0aW9uIFJv
        b3QwIBcNMjYxMDE2MTgyMjQ3WhgPMjA1MTEwMTYxODIyNDdaMDUxEDAOBgNVBAoM
        B09oclRlY2gxITAfBgNVBAMMGE9oclRlY2ggQXR0ZXN0YXRpb24gUm9vdDB2MBAG
        ByqGSM49AgEGBSuBBAAiA2IABDZ43Q4mMK7btCvQISVI7cu4hNo18hbdx9iV23q7
        PGTTd6HEiEKz4vZLovZiI/0EcZvDIVt0QtYSmSS2bX/g0zzeS4pfyB4F/xLCQry/
        f5Mi9GvR/AUQfumFXU9hSnOKg6NCMEAwDwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8B
        Af8EBAMCAQYwHQYDVR0OBBYEFA0qVN1WC69y2haBOak0vVlRvfDTMAoGCCqGSM49
        BAMDA2gAMGUCMQD8BgtALP/66zDO4fb7nAvmuGxSnYJTwMuaM0B2K7JRRsec5bpH
        1QNrurWUtK7YelwCMFoKiKKbh/e3tIVvxznrjsDA8s2Q8rRKmcwu3uU0tRVKL9YF
        k2A2bwkPZUJB93R0Wg==
        -----END CERTIFICATE-----
        """;

    /// <summary>SHA-256 of OhrTech's verified boot key, as an attestation's root of trust reports it.</summary>
    public const string VerifiedBootKeySha256 = "2beb1f5c24417c079046e60db3348bba47858b4990eeda2f5b88729507ff2ada";

    /// <summary>
    /// Extended key usage of the certificate that signs the attestation status list ("OhrTech Attestation Status N").
    /// A UUID OID (X.667).
    /// </summary>
    public const string StatusSigningEku = "2.25.73147592544128211943638446974928104936";

    /// <summary>How a unit attestation key certificate names its device: URI urn:ohrtech:device:dev_….</summary>
    public const string DeviceUriPrefix = "urn:ohrtech:device:";

    internal const string KeyDescriptionOid = "1.3.6.1.4.1.11129.2.1.17";

    /// <summary>The root, loaded.</summary>
    public static X509Certificate2 LoadRoot() => X509Certificate2.CreateFromPem(RootPem);
}

/// <summary>
/// What your server requires of an attestation beyond a chain that verifies. By default: verified boot,
/// locked, on OhrTech's boot key. Set <see cref="PackageName"/> (and <see cref="SignerSha256"/>) to your app.
/// </summary>
public sealed class DeviceAttestationPolicy
{
    /// <summary>Verified boot Verified, bootloader locked, and OhrTech's boot key. Default true.</summary>
    public bool RequireOhrTechBoot { get; init; } = true;

    /// <summary>The oldest OS security patch level accepted, YYYYMM (for example 202610).</summary>
    public int? MinOsPatchLevel { get; init; }

    /// <summary>Your app's package name: the key must be its.</summary>
    public string? PackageName { get; init; }

    /// <summary>SHA-256 of your app's signing certificate, hex: the app must be signed with it.</summary>
    public string? SignerSha256 { get; init; }
}

/// <summary>
/// The verdict. Accept only <see cref="Valid"/> with no <see cref="Problems"/>, then keep
/// <see cref="EcPublicKey"/> (and <see cref="MlDsa65PublicKey"/>) for the device: <see cref="AttestationToken.Verify"/>
/// checks each request with them.
/// </summary>
/// <param name="Valid">The chain(s) verify to the OhrTech Attestation Root through a named unit, the key is in the TEE,
/// the challenge matches, and (with a status list) the unit's keys aren't revoked.</param>
/// <param name="Problems">What fails <see cref="DeviceAttestationPolicy"/>.</param>
/// <param name="DeviceId">The OhrTech unit that made the key (dev_…).</param>
/// <param name="UnitCertificateSerials">The unit attestation key certificates (lowercase hex), as the status list lists them.</param>
public sealed record DeviceAttestationResult(bool Valid, string? Reason, IReadOnlyList<string> Problems, string Suite,
    string? DeviceId, IReadOnlyList<string> UnitCertificateSerials, string? PackageName, long? VersionCode,
    IReadOnlyList<string> SignerSha256, string? SecurityLevel, string? VerifiedBootState, bool? DeviceLocked,
    string? VerifiedBootKeySha256, int? OsVersion, int? OsPatchLevel, int? VendorPatchLevel, int? BootPatchLevel,
    byte[]? EcPublicKey, byte[]? MlDsa65PublicKey)
{
    /// <summary>Valid, and nothing fails the policy.</summary>
    public bool Accepted => Valid && Problems.Count == 0;
}

/// <summary>
/// Checks a Device SDK attestation (<c>OhrAttestation.attest</c>) on your server, offline: the chain to the OhrTech
/// Attestation Root, what KeyMint attests (the app, the boot state, patch levels, your challenge), the unit, and a
/// policy. Pass a current <see cref="AttestationStatusList"/> to refuse revoked units. Online, the Management API's
/// <c>VerifyAttestationAsync</c> does the same and also names the fleet and the app, for your own devices.
/// </summary>
public sealed class DeviceAttestationVerifier
{
    private readonly X509Certificate2 _root;
    private readonly DeviceAttestationPolicy _policy;

    public DeviceAttestationVerifier(DeviceAttestationPolicy? policy = null, X509Certificate2? root = null)
    {
        _policy = policy ?? new DeviceAttestationPolicy();
        _root = root ?? OhrTechAttestation.LoadRoot();
    }

    /// <summary>
    /// Checks the attestation as the app's <c>Attestation.toJson()</c> sends it:
    /// <c>{"suite", "ec": [base64 DER…], "mlDsa65"?: [...]}</c>, each chain the key's certificate first.
    /// </summary>
    public DeviceAttestationResult Verify(string attestationJson, byte[] challenge, AttestationStatusList? status = null, DateTimeOffset? at = null)
    {
        using var doc = JsonDocument.Parse(attestationJson);
        var root = doc.RootElement;
        static List<byte[]> Chain(JsonElement e) => e.EnumerateArray().Select(c => Convert.FromBase64String(c.GetString()!)).ToList();
        var ec = Chain(root.GetProperty("ec"));
        var ml = root.TryGetProperty("mlDsa65", out var m) && m.ValueKind == JsonValueKind.Array ? Chain(m) : null;
        var suite = root.TryGetProperty("suite", out var s) ? s.GetString() : null;
        if (suite != null && suite != (ml == null ? AttestationSuite.Ec : AttestationSuite.EcMlDsa65))
            return Fail(suite, $"the suite says {suite}, the chains say otherwise");
        return Verify(ec, ml, challenge, status, at);
    }

    /// <summary>Checks the EC key's chain and, for the post-quantum suite, the ML-DSA-65 key's (both must pass).</summary>
    public DeviceAttestationResult Verify(IReadOnlyList<byte[]> ecChain, IReadOnlyList<byte[]>? mlDsa65Chain, byte[] challenge,
        AttestationStatusList? status = null, DateTimeOffset? at = null)
    {
        var suite = mlDsa65Chain is { Count: > 0 } ? AttestationSuite.EcMlDsa65 : AttestationSuite.Ec;
        var now = at ?? DateTimeOffset.UtcNow;
        var ec = KeyChain.Verify(ecChain, _root, challenge, now);
        if (ec.Reason != null) return Fail(suite, ec.Reason);
        if (ec.Algorithm != "EC") return Fail(suite, "the first key is not an EC key");
        KeyChain? pq = null;
        if (suite == AttestationSuite.EcMlDsa65)
        {
            pq = KeyChain.Verify(mlDsa65Chain!, _root, challenge, now);
            if (pq.Reason != null) return Fail(suite, "the ML-DSA-65 key: " + pq.Reason);
            if (pq.Algorithm != "ML-DSA-65") return Fail(suite, "the second key is not an ML-DSA-65 key");
            if (pq.DeviceId != ec.DeviceId) return Fail(suite, "the two keys come from different units");
            if (!pq.Packages.Select(p => p.Name).SequenceEqual(ec.Packages.Select(p => p.Name))) return Fail(suite, "the two keys belong to different apps");
        }

        var serials = new[] { ec.UnitSerial, pq?.UnitSerial }.OfType<string>().Distinct().ToList();
        string? reason = null;
        if (status != null)
        {
            if (now > status.ExpiresAt) reason = "the status list has expired: fetch a new one";
            else if (serials.Select(x => status.Entries.TryGetValue(x, out var e) ? e : null).FirstOrDefault(e => e != null) is { } revoked)
                reason = $"OhrTech no longer vouches for this device's attestation keys ({revoked.Reason})";
        }

        var hw = ec.Hardware;
        var problems = new List<string>();
        if (reason == null)
        {
            if (_policy.RequireOhrTechBoot)
            {
                if (hw.VerifiedBootState != "verified") problems.Add($"verified boot is {hw.VerifiedBootState ?? "unknown"}, not verified");
                if (hw.DeviceLocked != true) problems.Add("the bootloader is not locked");
                if (hw.VerifiedBootKey == null || !Convert.ToHexStringLower(hw.VerifiedBootKey).Equals(OhrTechAttestation.VerifiedBootKeySha256, StringComparison.Ordinal))
                    problems.Add("the device did not boot with OhrTech's key");
            }
            if (_policy.MinOsPatchLevel is { } min && (ec.OsPatchLevel ?? 0) < min) problems.Add($"OS patch level {ec.OsPatchLevel} is older than {min}");
            if (_policy.PackageName is { } pkg && ec.Packages.All(p => p.Name != pkg)) problems.Add($"the key is not {pkg}'s");
            if (_policy.SignerSha256 is { } signer && !ec.SignerDigests.Any(d => Convert.ToHexStringLower(d).Equals(signer, StringComparison.OrdinalIgnoreCase)))
                problems.Add("the app is not signed with the expected key");
        }

        var first = ec.Packages.FirstOrDefault();
        return new DeviceAttestationResult(reason == null, reason, problems, suite, ec.DeviceId, serials, first?.Name, first?.Version,
            ec.SignerDigests.Select(Convert.ToHexStringLower).ToList(), ec.SecurityLevel, hw.VerifiedBootState, hw.DeviceLocked,
            hw.VerifiedBootKey == null ? null : Convert.ToHexStringLower(hw.VerifiedBootKey), ec.OsVersion, ec.OsPatchLevel,
            ec.VendorPatchLevel, ec.BootPatchLevel, ec.PublicKey, pq?.PublicKey);
    }

    private static DeviceAttestationResult Fail(string suite, string reason) =>
        new(false, reason, [], suite, null, [], null, null, [], null, null, null, null, null, null, null, null, null, null);

    // ── One key's chain ──

    private sealed record Package(string Name, long Version);

    private sealed record Authorizations(List<Package>? Packages, List<byte[]>? SignerDigests, bool? DeviceLocked,
        string? VerifiedBootState, byte[]? VerifiedBootKey, int? OsVersion, int? OsPatchLevel, int? VendorPatchLevel, int? BootPatchLevel);

    private sealed record KeyChain(string? Reason, string? DeviceId = null, string? UnitSerial = null, string? Algorithm = null,
        byte[]? PublicKey = null, string? SecurityLevel = null, Authorizations Hardware = null!, Authorizations Software = null!)
    {
        public List<Package> Packages => Hardware.Packages ?? Software.Packages ?? [];
        public List<byte[]> SignerDigests => Hardware.SignerDigests ?? Software.SignerDigests ?? [];
        public int? OsVersion => Hardware.OsVersion ?? Software.OsVersion;
        public int? OsPatchLevel => Hardware.OsPatchLevel ?? Software.OsPatchLevel;
        public int? VendorPatchLevel => Hardware.VendorPatchLevel ?? Software.VendorPatchLevel;
        public int? BootPatchLevel => Hardware.BootPatchLevel ?? Software.BootPatchLevel;

        public static KeyChain Verify(IReadOnlyList<byte[]> chain, X509Certificate2 root, byte[] challenge, DateTimeOffset now)
        {
            if (chain.Count < 3) return new KeyChain("the chain is too short: the key's certificate, the unit's and the intermediate at least");
            var certs = new List<X509Certificate2>();
            try
            {
                foreach (var der in chain) certs.Add(X509CertificateLoader.LoadCertificate(der));
                using var x = new X509Chain();
                x.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
                x.ChainPolicy.CustomTrustStore.Add(root);
                x.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
                x.ChainPolicy.VerificationTime = now.UtcDateTime;
                // KeyMint's validity on app key certificates says nothing about the key (often 1970 to 2048).
                x.ChainPolicy.VerificationFlags = X509VerificationFlags.IgnoreNotTimeValid;
                foreach (var c in certs.Skip(1)) x.ChainPolicy.ExtraStore.Add(c);
                if (!x.Build(certs[0]))
                    return new KeyChain("the chain does not verify to the OhrTech Attestation Root: " +
                                        string.Join("; ", x.ChainStatus.Select(s => s.StatusInformation.Trim()).Distinct()));
                if (!x.ChainElements[^1].Certificate.RawDataMemory.Span.SequenceEqual(root.RawDataMemory.Span))
                    return new KeyChain("the chain does not end at the OhrTech Attestation Root");
                if (x.ChainElements.Count != 4)
                    return new KeyChain($"the chain has {x.ChainElements.Count} certificates, not 4 (key, unit, intermediate, root)");
                var unit = x.ChainElements[1].Certificate;
                if (now.UtcDateTime < unit.NotBefore.ToUniversalTime() || now.UtcDateTime > unit.NotAfter.ToUniversalTime())
                    return new KeyChain("the unit's attestation key certificate has expired");
                var deviceId = DeviceIdOf(unit);
                if (deviceId == null) return new KeyChain("the unit's attestation key certificate does not name the device");

                var leaf = certs[0];
                var ext = leaf.Extensions.FirstOrDefault(e => e.Oid?.Value == OhrTechAttestation.KeyDescriptionOid);
                if (ext == null) return new KeyChain("the key's certificate has no attestation (KeyDescription)");
                var d = new AsnReader(ext.RawData, AsnEncodingRules.DER).ReadSequence();
                d.ReadInteger(); // attestationVersion
                var level = Level(Enum(d));
                d.ReadInteger(); // keyMintVersion
                var kmLevel = Level(Enum(d));
                var attested = d.ReadOctetString();
                d.ReadOctetString(); // uniqueId
                var sw = ReadAuthorizations(d.ReadSequence());
                var hw = ReadAuthorizations(d.ReadSequence());
                if (level is not ("tee" or "strongbox") || kmLevel is not ("tee" or "strongbox"))
                    return new KeyChain($"the key is not in the TEE (attestation {level}, KeyMint {kmLevel})");
                if (!CryptographicOperations.FixedTimeEquals(attested, challenge)) return new KeyChain("the challenge does not match");
                var algorithm = leaf.PublicKey.Oid.Value switch
                {
                    "1.2.840.10045.2.1" => "EC",
                    "2.16.840.1.101.3.4.3.18" => "ML-DSA-65",
                    var o => o
                };
                return new KeyChain(null, deviceId, unit.SerialNumber.ToLowerInvariant(), algorithm, leaf.PublicKey.ExportSubjectPublicKeyInfo(),
                    level, hw, sw);
            }
            catch (Exception e) when (e is AsnContentException or CryptographicException or InvalidOperationException)
            {
                return new KeyChain("the attestation can't be read: " + e.Message);
            }
            finally
            {
                certs.ForEach(c => c.Dispose());
            }
        }
    }

    /// <summary>The device id (dev_…) a unit attestation key certificate names (subject alternative name URI).</summary>
    public static string? DeviceIdOf(X509Certificate2 unit)
    {
        var san = unit.Extensions.FirstOrDefault(e => e.Oid?.Value == "2.5.29.17");
        if (san == null) return null;
        var names = new AsnReader(san.RawData, AsnEncodingRules.DER).ReadSequence();
        var uriTag = new Asn1Tag(TagClass.ContextSpecific, 6);
        while (names.HasData)
        {
            if (names.PeekTag() != uriTag)
            {
                names.ReadEncodedValue();
                continue;
            }
            var uri = names.ReadCharacterString(UniversalTagNumber.IA5String, uriTag);
            if (uri.StartsWith(OhrTechAttestation.DeviceUriPrefix, StringComparison.Ordinal)) return uri[OhrTechAttestation.DeviceUriPrefix.Length..];
        }
        return null;
    }

    private static int Enum(AsnReader r)
    {
        var v = 0;
        foreach (var b in r.ReadEnumeratedBytes().Span) v = (v << 8) | b;
        return v;
    }

    private static string Level(int v) => v switch { 0 => "software", 1 => "tee", 2 => "strongbox", _ => $"unknown {v}" };

    // KeyDescription's AuthorizationList (hardware/interfaces/security/keymint): the tags this verifier reads.
    private static Authorizations ReadAuthorizations(AsnReader list)
    {
        List<Package>? packages = null;
        List<byte[]>? digests = null;
        bool? locked = null;
        string? bootState = null;
        byte[]? bootKey = null;
        int? os = null, osPatch = null, vendorPatch = null, bootPatch = null;
        while (list.HasData)
        {
            var tag = list.PeekTag();
            if (tag.TagClass != TagClass.ContextSpecific)
            {
                list.ReadEncodedValue();
                continue;
            }
            var field = list.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, tag.TagValue, true));
            switch (tag.TagValue)
            {
                case 704: // rootOfTrust
                {
                    var rot = field.ReadSequence();
                    bootKey = rot.ReadOctetString();
                    locked = rot.ReadBoolean();
                    bootState = Enum(rot) switch { 0 => "verified", 1 => "self-signed", 2 => "unverified", 3 => "failed", var s => $"unknown {s}" };
                    break;
                }
                case 705: os = (int) field.ReadInteger(); break;
                case 706: osPatch = (int) field.ReadInteger(); break;
                case 718: vendorPatch = (int) field.ReadInteger(); break;
                case 719: bootPatch = (int) field.ReadInteger(); break;
                case 709: // attestationApplicationId
                {
                    var app = new AsnReader(field.ReadOctetString(), AsnEncodingRules.DER).ReadSequence();
                    var infos = app.ReadSetOf(skipSortOrderValidation: true);
                    packages = [];
                    while (infos.HasData)
                    {
                        var info = infos.ReadSequence();
                        packages.Add(new Package(Encoding.UTF8.GetString(info.ReadOctetString()), (long) info.ReadInteger()));
                    }
                    var sigs = app.ReadSetOf(skipSortOrderValidation: true);
                    digests = [];
                    while (sigs.HasData) digests.Add(sigs.ReadOctetString());
                    break;
                }
                default:
                    field.ReadEncodedValue();
                    break;
            }
        }
        return new Authorizations(packages, digests, locked, bootState, bootKey, os, osPatch, vendorPatch, bootPatch);
    }
}

/// <summary>One revoked unit attestation key certificate.</summary>
public sealed record AttestationStatusEntry(string Status, string Reason, DateTimeOffset RevokedAt);

/// <summary>
/// The unit attestation key certificates OhrTech no longer vouches for (a lost, retired or compromised unit), signed by
/// the OhrTech Attestation Status certificate under the OhrTech root. Good for 24 hours: fetch it again before
/// <see cref="ExpiresAt"/> (a few times a day is plenty) and pass it to <see cref="DeviceAttestationVerifier.Verify(string, byte[], AttestationStatusList?, DateTimeOffset?)"/>.
/// </summary>
public sealed class AttestationStatusList
{
    public const string DefaultUrl = "https://api.ohrtech.net/v1/attestations/status";

    public DateTimeOffset IssuedAt { get; }
    public DateTimeOffset ExpiresAt { get; }

    /// <summary>Revoked unit certificates by serial, lowercase hex.</summary>
    public IReadOnlyDictionary<string, AttestationStatusEntry> Entries { get; }

    private AttestationStatusList(DateTimeOffset issuedAt, DateTimeOffset expiresAt, Dictionary<string, AttestationStatusEntry> entries)
    {
        IssuedAt = issuedAt;
        ExpiresAt = expiresAt;
        Entries = entries;
    }

    /// <summary>Fetches the list (no sign-in) and opens it.</summary>
    public static async Task<AttestationStatusList> FetchAsync(HttpClient http, string url = DefaultUrl, CancellationToken cancellationToken = default)
    {
        var jws = await http.GetStringAsync(url, cancellationToken).ConfigureAwait(false);
        return Open(jws);
    }

    /// <summary>
    /// Opens the signed list: an ES256 JWS whose x5c is the status certificate and its intermediate. Checks the
    /// signature, that the status certificate is issued by an intermediate under <paramref name="root"/> (the OhrTech
    /// root by default), is not a CA and has <see cref="OhrTechAttestation.StatusSigningEku"/>, and that the list hasn't
    /// expired. Throws <see cref="CryptographicException"/> when any of that fails.
    /// </summary>
    public static AttestationStatusList Open(string jws, X509Certificate2? root = null, DateTimeOffset? at = null)
    {
        var now = at ?? DateTimeOffset.UtcNow;
        var parts = jws.Trim().Split('.');
        if (parts.Length != 3) throw new CryptographicException("the status list is not a JWS");
        try
        {
            using var header = JsonDocument.Parse(Base64Url.DecodeFromChars(parts[0]));
            if (header.RootElement.GetProperty("alg").GetString() != "ES256") throw new CryptographicException("the status list is not ES256");
            var x5c = header.RootElement.GetProperty("x5c").EnumerateArray().Select(e => Convert.FromBase64String(e.GetString()!)).ToList();
            if (x5c.Count != 2) throw new CryptographicException("x5c is the status certificate and its intermediate");
            using var signer = X509CertificateLoader.LoadCertificate(x5c[0]);
            using var intermediate = X509CertificateLoader.LoadCertificate(x5c[1]);
            using var trust = root == null ? OhrTechAttestation.LoadRoot() : null;
            using var chain = new X509Chain();
            chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
            chain.ChainPolicy.CustomTrustStore.Add(root ?? trust!);
            chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
            chain.ChainPolicy.VerificationTime = now.UtcDateTime;
            chain.ChainPolicy.ExtraStore.Add(intermediate);
            chain.ChainPolicy.ApplicationPolicy.Add(new Oid(OhrTechAttestation.StatusSigningEku));
            if (!chain.Build(signer) || chain.ChainElements.Count != 3)
                throw new CryptographicException("the status certificate does not verify to the OhrTech Attestation Root");
            if (signer.Extensions.OfType<X509BasicConstraintsExtension>().FirstOrDefault() is not { CertificateAuthority: false } ||
                signer.Extensions.OfType<X509EnhancedKeyUsageExtension>().FirstOrDefault()?.EnhancedKeyUsages[OhrTechAttestation.StatusSigningEku] == null)
                throw new CryptographicException("the signer is not an OhrTech Attestation Status certificate");
            using var key = signer.GetECDsaPublicKey() ?? throw new CryptographicException("the status certificate has no EC key");
            if (!key.VerifyData(Encoding.ASCII.GetBytes(parts[0] + "." + parts[1]), Base64Url.DecodeFromChars(parts[2]),
                    HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation))
                throw new CryptographicException("the status list's signature does not verify");

            using var payload = JsonDocument.Parse(Base64Url.DecodeFromChars(parts[1]));
            var p = payload.RootElement;
            var expires = DateTimeOffset.FromUnixTimeSeconds(p.GetProperty("exp").GetInt64());
            if (now > expires) throw new CryptographicException("the status list has expired");
            var entries = new Dictionary<string, AttestationStatusEntry>();
            foreach (var e in p.GetProperty("entries").EnumerateObject())
                entries[e.Name] = new AttestationStatusEntry(e.Value.GetProperty("status").GetString()!, e.Value.GetProperty("reason").GetString()!,
                    e.Value.GetProperty("revokedAt").GetDateTimeOffset());
            return new AttestationStatusList(DateTimeOffset.FromUnixTimeSeconds(p.GetProperty("iat").GetInt64()), expires, entries);
        }
        catch (Exception e) when (e is FormatException or JsonException or KeyNotFoundException or InvalidOperationException)
        {
            throw new CryptographicException("the status list can't be read: " + e.Message, e);
        }
    }
}

/// <summary>What a verified <see cref="AttestationToken"/> says.</summary>
public sealed record AttestationTokenClaims(string Audience, DateTimeOffset IssuedAt, DateTimeOffset ExpiresAt, string? Nonce);

/// <summary>
/// The per-request proof the Device SDK's <c>OhrAttestation.token(audience)</c> makes with the attested key(s):
/// <c>header.payload.ecSignature[.mlDsa65Signature]</c>, base64url; header <c>{"typ":"ohr-attest","alg":"ES256"}</c> or
/// <c>"ES256+ML-DSA-65"</c>, payload <c>{"aud","iat","exp",?"nonce"}</c>. An ES256 token is a standard JWS.
/// </summary>
public static class AttestationToken
{
    /// <summary>
    /// Verifies a token against the keys you kept from the attestation (<see cref="DeviceAttestationResult.EcPublicKey"/>
    /// and, for the post-quantum suite, <see cref="DeviceAttestationResult.MlDsa65PublicKey"/>; with both, the token
    /// must carry both signatures). Checks the audience, and the time within <paramref name="clockSkew"/> (default
    /// 60 s). A token lives at most <paramref name="maxLifetime"/> (default 10 minutes). Replay within its lifetime is
    /// yours to stop: send a nonce and check it. Throws <see cref="CryptographicException"/> when it fails.
    /// </summary>
    public static AttestationTokenClaims Verify(string token, string audience, byte[] ecPublicKey, byte[]? mlDsa65PublicKey = null,
        DateTimeOffset? at = null, TimeSpan? clockSkew = null, TimeSpan? maxLifetime = null)
    {
        var parts = token.Split('.');
        var hybrid = mlDsa65PublicKey != null;
        if (parts.Length != (hybrid ? 4 : 3))
            throw new CryptographicException(hybrid ? "the token has no ML-DSA-65 signature" : "not an ES256 attestation token");
        try
        {
            using var header = JsonDocument.Parse(Base64Url.DecodeFromChars(parts[0]));
            var h = header.RootElement;
            if (h.GetProperty("typ").GetString() != "ohr-attest") throw new CryptographicException("not an OhrTech attestation token");
            var alg = h.GetProperty("alg").GetString();
            if (alg != (hybrid ? "ES256+ML-DSA-65" : "ES256")) throw new CryptographicException($"the token is {alg}, not this device's suite");

            var signed = Encoding.ASCII.GetBytes(parts[0] + "." + parts[1]);
            using (var ec = ECDsa.Create())
            {
                ec.ImportSubjectPublicKeyInfo(ecPublicKey, out _);
                if (!ec.VerifyData(signed, Base64Url.DecodeFromChars(parts[2]), HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation))
                    throw new CryptographicException("the EC signature does not verify");
            }
            if (hybrid)
            {
                using var ml = MLDsa.ImportMLDsaPublicKey(MLDsaAlgorithm.MLDsa65, MlDsa65Key(mlDsa65PublicKey!));
                if (!ml.VerifyData(signed, Base64Url.DecodeFromChars(parts[3])))
                    throw new CryptographicException("the ML-DSA-65 signature does not verify");
            }

            using var payload = JsonDocument.Parse(Base64Url.DecodeFromChars(parts[1]));
            var p = payload.RootElement;
            var aud = p.GetProperty("aud").GetString();
            if (aud != audience) throw new CryptographicException($"the token is for {aud}");
            var iat = DateTimeOffset.FromUnixTimeSeconds(p.GetProperty("iat").GetInt64());
            var exp = DateTimeOffset.FromUnixTimeSeconds(p.GetProperty("exp").GetInt64());
            var now = at ?? DateTimeOffset.UtcNow;
            var skew = clockSkew ?? TimeSpan.FromSeconds(60);
            if (exp - iat > (maxLifetime ?? TimeSpan.FromMinutes(10))) throw new CryptographicException("the token lives too long");
            if (now + skew < iat) throw new CryptographicException("the token is from the future");
            if (now - skew > exp) throw new CryptographicException("the token has expired");
            var nonce = p.TryGetProperty("nonce", out var n) ? n.GetString() : null;
            return new AttestationTokenClaims(aud!, iat, exp, nonce);
        }
        catch (Exception e) when (e is FormatException or JsonException or KeyNotFoundException or InvalidOperationException)
        {
            throw new CryptographicException("the token can't be read: " + e.Message, e);
        }
    }

    /// <summary>The raw ML-DSA-65 public key in a SubjectPublicKeyInfo (id-ml-dsa-65, 2.16.840.1.101.3.4.3.18).</summary>
    private static byte[] MlDsa65Key(byte[] spki)
    {
        try
        {
            var seq = new AsnReader(spki, AsnEncodingRules.DER).ReadSequence();
            var alg = seq.ReadSequence();
            if (alg.ReadObjectIdentifier() != "2.16.840.1.101.3.4.3.18") throw new CryptographicException("the second key is not ML-DSA-65");
            return seq.ReadBitString(out _);
        }
        catch (AsnContentException e)
        {
            throw new CryptographicException("the ML-DSA-65 key can't be read", e);
        }
    }
}
#endif
