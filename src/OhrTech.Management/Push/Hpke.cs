#if NET10_0_OR_GREATER
using System;
using System.Security.Cryptography;
using Org.BouncyCastle.Math.EC.Rfc7748;

namespace OhrTech.Management.Push;

/// <summary>
/// HPKE (RFC 9180) base mode, sender side, for the two push suites: DHKEM(X25519, HKDF-SHA256)
/// and X-Wing, each with HKDF-SHA256 and AES-128-GCM, one message per context. The device opens
/// with BoringSSL in its TEE.
/// </summary>
internal static class Hpke
{
    public const ushort KemX25519 = 0x0020, KemXWing = 0x647a, KdfHkdfSha256 = 0x0001, AeadAes128Gcm = 0x0001;
    public const int X25519KeySize = 32, XWingPublicKeySize = 1216, XWingEncSize = 1120;

    private static readonly byte[] Version = "HPKE-v1"u8.ToArray();
    private static readonly byte[] XWingLabel = [0x5c, 0x2e, 0x2f, 0x2f, 0x5e, 0x5c];

    /// <summary>The encapsulated key and the ciphertext (with its 16-byte tag).</summary>
    public sealed record Sealed(byte[] Enc, byte[] Ciphertext);

    public static Sealed Seal(ushort kem, byte[] recipientPublicKey, byte[] info, byte[] aad, byte[] plaintext)
    {
        var (shared, enc) = kem switch
        {
            KemX25519 => DhkemEncap(recipientPublicKey),
            KemXWing => XWingEncap(recipientPublicKey),
            _ => throw new ArgumentException($"KEM 0x{kem:x4} is not a push KEM", nameof(kem))
        };
        try
        {
            var (key, nonce) = KeySchedule(kem, shared, info);
            var ct = new byte[plaintext.Length + 16];
            using var gcm = new AesGcm(key, 16);
            gcm.Encrypt(nonce, plaintext, ct.AsSpan(0, plaintext.Length), ct.AsSpan(plaintext.Length), aad);
            CryptographicOperations.ZeroMemory(key);
            return new Sealed(enc, ct);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(shared);
        }
    }

    // ── KEMs ─────────────────────────────────────────────────────────────────────────────────

    private static (byte[] Shared, byte[] Enc) DhkemEncap(byte[] pkR)
    {
        if (pkR.Length != X25519KeySize) throw new ArgumentException("an X25519 public key is 32 bytes");
        var skE = RandomNumberGenerator.GetBytes(32);
        var pkE = X25519Public(skE);
        var dh = new byte[32];
        if (!X25519.CalculateAgreement(skE, 0, pkR, 0, dh, 0))
            throw new CryptographicException("the X25519 public key is of low order");
        CryptographicOperations.ZeroMemory(skE);
        // ExtractAndExpand(dh, kem_context = enc || pkR) with suite_id "KEM" || kem id.
        byte[] suite = [(byte) 'K', (byte) 'E', (byte) 'M', KemX25519 >> 8, KemX25519 & 0xff];
        var prk = LabeledExtract(suite, [], "eae_prk"u8, dh);
        var shared = LabeledExpand(suite, prk, "shared_secret"u8, [..pkE, ..pkR], 32);
        CryptographicOperations.ZeroMemory(dh);
        CryptographicOperations.ZeroMemory(prk);
        return (shared, pkE);
    }

    private static (byte[] Shared, byte[] Enc) XWingEncap(byte[] pk)
    {
        if (pk.Length != XWingPublicKeySize) throw new ArgumentException("an X-Wing public key is 1216 bytes");
        var pkM = pk[..1184];
        var pkX = pk[1184..];
        using var mlkem = MLKem.ImportEncapsulationKey(MLKemAlgorithm.MLKem768, pkM);
        mlkem.Encapsulate(out var ctM, out var ssM);
        var ekX = RandomNumberGenerator.GetBytes(32);
        var ctX = X25519Public(ekX);
        var ssX = new byte[32];
        if (!X25519.CalculateAgreement(ekX, 0, pkX, 0, ssX, 0))
            throw new CryptographicException("the X-Wing X25519 key is of low order");
        CryptographicOperations.ZeroMemory(ekX);
        var shared = SHA3_256.HashData([..ssM, ..ssX, ..ctX, ..pkX, ..XWingLabel]);
        CryptographicOperations.ZeroMemory(ssM);
        CryptographicOperations.ZeroMemory(ssX);
        return (shared, [..ctM, ..ctX]);
    }

    public static byte[] X25519Public(byte[] privateKey)
    {
        var pub = new byte[32];
        X25519.GeneratePublicKey(privateKey, 0, pub, 0);
        return pub;
    }

    /// <summary>
    /// The public key of an X-Wing private key (its 32-byte seed), as BoringSSL derives it:
    /// SHAKE256(seed, 96) = ML-KEM-768 seed (64) || X25519 private key (32). For tests and tools.
    /// </summary>
    public static byte[] XWingPublic(byte[] seed)
    {
        var expanded = Shake256.HashData(seed, 96);
        using var mlkem = MLKem.ImportPrivateSeed(MLKemAlgorithm.MLKem768, expanded[..64]);
        var pub = (byte[]) [..mlkem.ExportEncapsulationKey(), ..X25519Public(expanded[64..])];
        CryptographicOperations.ZeroMemory(expanded);
        return pub;
    }

    // ── Key schedule ─────────────────────────────────────────────────────────────────────────

    private static (byte[] Key, byte[] Nonce) KeySchedule(ushort kem, byte[] shared, byte[] info)
    {
        byte[] suite = [(byte) 'H', (byte) 'P', (byte) 'K', (byte) 'E', (byte) (kem >> 8), (byte) kem,
            KdfHkdfSha256 >> 8, KdfHkdfSha256 & 0xff, AeadAes128Gcm >> 8, AeadAes128Gcm & 0xff];
        var pskIdHash = LabeledExtract(suite, [], "psk_id_hash"u8, []);
        var infoHash = LabeledExtract(suite, [], "info_hash"u8, info);
        byte[] context = [0x00, ..pskIdHash, ..infoHash]; // mode_base
        var secret = LabeledExtract(suite, shared, "secret"u8, []);
        var key = LabeledExpand(suite, secret, "key"u8, context, 16);
        var nonce = LabeledExpand(suite, secret, "base_nonce"u8, context, 12);
        CryptographicOperations.ZeroMemory(secret);
        return (key, nonce); // sequence 0: the base nonce itself
    }

    private static byte[] LabeledExtract(byte[] suite, byte[] salt, ReadOnlySpan<byte> label, byte[] ikm) =>
        HKDF.Extract(HashAlgorithmName.SHA256, [..Version, ..suite, ..label, ..ikm], salt);

    private static byte[] LabeledExpand(byte[] suite, byte[] prk, ReadOnlySpan<byte> label, byte[] info, int length) =>
        HKDF.Expand(HashAlgorithmName.SHA256, prk, length,
            [(byte) (length >> 8), (byte) length, ..Version, ..suite, ..label, ..info]);
}
#endif
