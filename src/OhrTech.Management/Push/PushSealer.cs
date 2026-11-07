#if NET10_0_OR_GREATER
using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;

namespace OhrTech.Management.Push;

/// <summary>
/// The push suites. <see cref="X25519"/> is small (about 110 bytes added to a message) and the
/// default; <see cref="XWingMlDsa65"/> is post-quantum (about 4.6 KB added): choose it for messages
/// whose content must stay secret for years. A token has one suite; seal with that one.
/// </summary>
public static class PushSuite
{
    public const string X25519 = "x25519";
    public const string XWingMlDsa65 = "xwing-mldsa65";

    internal static ushort Kem(string suite) => suite switch
    {
        X25519 => Hpke.KemX25519,
        XWingMlDsa65 => Hpke.KemXWing,
        _ => throw new ArgumentException($"unknown push suite {suite}", nameof(suite))
    };

    internal static int PublicKeySize(string suite) => suite == X25519 ? 32 : Hpke.XWingPublicKeySize;
}

/// <summary>
/// Your server's push signing keys: Ed25519, and ML-DSA-65 for the post-quantum suite. Keep the
/// private seeds secret; give the app the public keys (<see cref="PublicKeys"/>) as its sender keys:
/// it accepts only messages they signed.
/// </summary>
public sealed class PushSenderKey : IDisposable
{
    /// <summary>What the app carries as one of its sender keys.</summary>
    public sealed record Public(byte[] Ed25519, byte[]? MlDsa65);

    private readonly byte[] _ed25519;
    private readonly MLDsa? _mlDsa;

    private PushSenderKey(byte[] ed25519, MLDsa? mlDsa)
    {
        _ed25519 = ed25519;
        _mlDsa = mlDsa;
    }

    /// <summary>New keys. <paramref name="postQuantum"/>: also ML-DSA-65, needed for <see cref="PushSuite.XWingMlDsa65"/>.</summary>
    public static PushSenderKey Generate(bool postQuantum = true) =>
        new(RandomNumberGenerator.GetBytes(32), postQuantum ? MLDsa.GenerateKey(MLDsaAlgorithm.MLDsa65) : null);

    /// <summary>Keys from their stored seeds (<see cref="Ed25519Seed"/>, <see cref="MlDsa65Seed"/>).</summary>
    public static PushSenderKey Import(byte[] ed25519Seed, byte[]? mlDsa65Seed)
    {
        if (ed25519Seed.Length != 32) throw new ArgumentException("an Ed25519 seed is 32 bytes", nameof(ed25519Seed));
        return new((byte[]) ed25519Seed.Clone(),
            mlDsa65Seed == null ? null : MLDsa.ImportMLDsaPrivateSeed(MLDsaAlgorithm.MLDsa65, mlDsa65Seed));
    }

    public Public PublicKeys => new(new Ed25519PrivateKeyParameters(_ed25519, 0).GeneratePublicKey().GetEncoded(),
        _mlDsa?.ExportMLDsaPublicKey());

    public byte[] Ed25519Seed => (byte[]) _ed25519.Clone();
    public byte[]? MlDsa65Seed => _mlDsa?.ExportMLDsaPrivateSeed();

    internal (byte[] Ed25519, byte[]? MlDsa65) Sign(byte[] data, bool postQuantum)
    {
        var s = new Ed25519Signer();
        s.Init(true, new Ed25519PrivateKeyParameters(_ed25519, 0));
        s.BlockUpdate(data, 0, data.Length);
        var ed = s.GenerateSignature();
        if (!postQuantum) return (ed, null);
        if (_mlDsa == null) throw new InvalidOperationException("the xwing-mldsa65 suite needs a sender key with ML-DSA-65");
        return (ed, _mlDsa.SignData(data));
    }

    public void Dispose()
    {
        CryptographicOperations.ZeroMemory(_ed25519);
        _mlDsa?.Dispose();
    }
}

/// <summary>
/// Seals and signs a push message for an app's push token, as <c>POST /v1/push</c> takes it. The
/// message is end to end: neither OhrTech nor the device's Agent can read it, and the app accepts
/// it only with a signature by one of its sender keys.
/// </summary>
public static class PushSealer
{
    public const int MaxData = 4096;
    private const string Label = "ohrtech-push-v1";

    /// <param name="token">The app's push token (psh_…).</param>
    /// <param name="suite">The token's suite (<see cref="PushSuite"/>).</param>
    /// <param name="recipientPublicKey">The token's public key, which the app sent your server with the token.</param>
    /// <param name="sender">Your signing keys.</param>
    /// <param name="id">Your id for the message (1-64 characters): the app drops a repeat.</param>
    /// <param name="expires">After this the app drops it.</param>
    /// <param name="data">At most 4,096 bytes.</param>
    /// <returns>The message: send it base64 as <c>message</c>.</returns>
    public static byte[] Seal(string token, string suite, byte[] recipientPublicKey, PushSenderKey sender, string id,
        DateTimeOffset expires, byte[] data)
    {
        if (data.Length > MaxData) throw new ArgumentException($"at most {MaxData} bytes of data", nameof(data));
        if (id.Length is 0 or > 64) throw new ArgumentException("the id is 1 to 64 characters", nameof(id));
        if (recipientPublicKey.Length != PushSuite.PublicKeySize(suite))
            throw new ArgumentException($"an {suite} public key is {PushSuite.PublicKeySize(suite)} bytes", nameof(recipientPublicKey));

        var p = new Cbor();
        p.Map(3).Text("id").Text(id).Text("exp").UInt((ulong) expires.ToUnixTimeSeconds()).Text("data").Bytes(data);
        var plaintext = p.ToArray();
        byte[] info = [..Encoding.ASCII.GetBytes(Label), 0x00, ..Encoding.ASCII.GetBytes(token)];
        var sealedMessage = Hpke.Seal(PushSuite.Kem(suite), recipientPublicKey, info, [], plaintext);
        CryptographicOperations.ZeroMemory(plaintext);

        var signed = new Cbor();
        signed.Array(5).Text(Label).Text(token).Text(suite).Bytes(sealedMessage.Enc).Bytes(sealedMessage.Ciphertext);
        var (ed, ml) = sender.Sign(signed.ToArray(), suite == PushSuite.XWingMlDsa65);

        var e = new Cbor();
        e.Map(5).Text("v").UInt(1).Text("suite").Text(suite).Text("enc").Bytes(sealedMessage.Enc)
            .Text("ct").Bytes(sealedMessage.Ciphertext).Text("sig").Map(ml == null ? 1 : 2).Text("ed25519").Bytes(ed);
        if (ml != null) e.Text("mldsa65").Bytes(ml);
        return e.ToArray();
    }

    /// <summary><see cref="Seal"/>, base64: what <c>message</c> takes.</summary>
    public static string SealBase64(string token, string suite, byte[] recipientPublicKey, PushSenderKey sender, string id,
        DateTimeOffset expires, byte[] data) =>
        Convert.ToBase64String(Seal(token, suite, recipientPublicKey, sender, id, expires, data));

    /// <summary>The few CBOR items a message needs (RFC 8949, definite lengths, shortest heads).</summary>
    private sealed class Cbor
    {
        private readonly MemoryStream _out = new();

        private Cbor Head(int major, ulong v)
        {
            var m = (byte) (major << 5);
            if (v < 24) _out.WriteByte((byte) (m | (int) v));
            else if (v <= byte.MaxValue) { _out.WriteByte((byte) (m | 24)); _out.WriteByte((byte) v); }
            else if (v <= ushort.MaxValue) { _out.WriteByte((byte) (m | 25)); Be(v, 2); }
            else if (v <= uint.MaxValue) { _out.WriteByte((byte) (m | 26)); Be(v, 4); }
            else { _out.WriteByte((byte) (m | 27)); Be(v, 8); }
            return this;
        }

        private void Be(ulong v, int n)
        {
            for (var i = n - 1; i >= 0; i--) _out.WriteByte((byte) (v >> (8 * i)));
        }

        public Cbor UInt(ulong v) => Head(0, v);

        public Cbor Bytes(byte[] b)
        {
            Head(2, (ulong) b.Length);
            _out.Write(b, 0, b.Length);
            return this;
        }

        public Cbor Text(string s)
        {
            var b = Encoding.UTF8.GetBytes(s);
            Head(3, (ulong) b.Length);
            _out.Write(b, 0, b.Length);
            return this;
        }

        public Cbor Array(int n) => Head(4, (ulong) n);
        public Cbor Map(int n) => Head(5, (ulong) n);
        public byte[] ToArray() => _out.ToArray();
    }
}
#endif
