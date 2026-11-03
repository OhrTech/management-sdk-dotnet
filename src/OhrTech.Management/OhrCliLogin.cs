using System;
using System.IO;
using System.Net.Http;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace OhrTech.Management
{
    public sealed partial class OhrUserSession
    {
        // Must match where and how the ohr CLI saves its login.
        private const string CliDefaultApi = "https://api.ohrtech.net";
        private static readonly byte[] CliDpapiEntropy = Encoding.UTF8.GetBytes("ohr-cli credentials v1");

        /// <summary>
        /// The person signed in to the ohr CLI (<c>ohr login</c>) on this computer, for quick scripts and
        /// development. For anything that runs unattended, use a service account instead.
        /// <para>
        /// Reads the CLI's saved login (<c>~/.config/ohr/credentials.json</c>, honouring
        /// <c>$XDG_CONFIG_HOME</c>; <c>%APPDATA%\ohr\credentials.json</c> on Windows) and never writes it:
        /// tokens this session refreshes stay in memory, and the CLI keeps its own login.
        /// It calls the API the CLI signed in to (<c>ohr login --api</c>).
        /// </para>
        /// </summary>
        /// <param name="innerHandler">The handler that sends requests; a new <see cref="HttpClientHandler"/> by default.</param>
        /// <exception cref="InvalidOperationException">The CLI is not signed in on this computer, or its login cannot be read.</exception>
        public static OhrUserSession FromOhrCli(HttpMessageHandler? innerHandler = null)
        {
            var path = OhrCliCredentialsPath;
            if (!File.Exists(path))
                throw new InvalidOperationException($"The ohr CLI is not signed in on this computer ({path} does not exist). Run 'ohr login'.");

            JsonElement root;
            try
            {
                using var doc = JsonDocument.Parse(File.ReadAllText(path));
                root = doc.RootElement.Clone();
            }
            catch (Exception e) when (e is JsonException or IOException or UnauthorizedAccessException)
            {
                throw new InvalidOperationException($"Cannot read the ohr CLI's login in {path} ({e.Message}). Run 'ohr login' again.", e);
            }

            string? S(string name) => root.ValueKind == JsonValueKind.Object && root.TryGetProperty(name, out var v) &&
                                      v.ValueKind == JsonValueKind.String ? v.GetString() : null;

            string? access = S("accessToken"), refresh = S("refreshToken");
            if (IsWindows)
            {
                access = Unprotect(S("accessTokenDpapi"), path) ?? access;
                refresh = Unprotect(S("refreshTokenDpapi"), path) ?? refresh;
            }
            if (string.IsNullOrEmpty(refresh))
                throw new InvalidOperationException($"The ohr CLI's login in {path} has no refresh token. Run 'ohr login' again.");

            var expires = DateTimeOffset.MinValue;
            if (!string.IsNullOrEmpty(access) && DateTimeOffset.TryParse(S("accessTokenExpiresAt"), out var e2)) expires = e2;
            var api = S("api") is { Length: > 0 } a ? a : CliDefaultApi;
            return new OhrUserSession(new Uri(api), string.IsNullOrEmpty(access) ? null : access, expires, refresh!, innerHandler);
        }

        /// <summary>Where the ohr CLI keeps its login on this computer (it may not exist).</summary>
        public static string OhrCliCredentialsPath
        {
            get
            {
                string dir;
                if (IsWindows)
                    dir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "ohr");
                else
                {
                    var xdg = Environment.GetEnvironmentVariable("XDG_CONFIG_HOME");
                    var config = !string.IsNullOrEmpty(xdg) && Path.IsPathRooted(xdg)
                        ? xdg!
                        : Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), ".config");
                    dir = Path.Combine(config, "ohr");
                }

                return Path.Combine(dir, "credentials.json");
            }
        }

        private static bool IsWindows => RuntimeInformation.IsOSPlatform(OSPlatform.Windows);

        /// <summary>On Windows the CLI keeps its tokens DPAPI-protected for the current user.</summary>
        private static string? Unprotect(string? blob, string path)
        {
            if (string.IsNullOrEmpty(blob)) return null;
            try
            {
#pragma warning disable CA1416 // only reached on Windows (IsWindows)
                return Encoding.UTF8.GetString(ProtectedData.Unprotect(Convert.FromBase64String(blob), CliDpapiEntropy,
                    DataProtectionScope.CurrentUser));
#pragma warning restore CA1416
            }
            catch (Exception e) when (e is CryptographicException or FormatException)
            {
                throw new InvalidOperationException(
                    $"The ohr CLI's login in {path} cannot be decrypted (was it copied from another Windows account?). Run 'ohr login' again.", e);
            }
        }
    }
}
