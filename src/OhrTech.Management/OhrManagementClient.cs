using System;
using System.Net.Http;

namespace OhrTech.Management
{
    /// <summary>
    /// The OhrTech Management API client. Every API call is a method generated from the OpenAPI document
    /// (Generated/OhrManagementClient.g.cs); this part adds the two ways to sign in:
    /// <list type="bullet">
    /// <item><see cref="ForServiceAccount"/>: an organisation's service account token (<c>ohrs_…</c>), for servers and automation.</item>
    /// <item><see cref="ForUser"/>: a person, signed in with <see cref="OhrUserSession.SignInAsync"/>; their access token is refreshed for you.</item>
    /// </list>
    /// To use your own <see cref="HttpClient"/> (IHttpClientFactory), give it <see cref="OhrServiceTokenHandler"/> or
    /// <see cref="OhrUserSessionHandler"/> and a <see cref="HttpClient.BaseAddress"/> of <see cref="DefaultBaseUrl"/>,
    /// then use the constructor.
    /// </summary>
    public partial class OhrManagementClient : IDisposable
    {
        /// <summary>https://api.ohrtech.net/</summary>
        public static readonly Uri DefaultBaseUrl = new Uri("https://api.ohrtech.net/");

        /// <summary>
        /// How long one call may take on the HttpClient these factories make: long enough to upload a large APK.
        /// Pass a CancellationToken for a shorter limit.
        /// </summary>
        public static readonly TimeSpan RequestTimeout = TimeSpan.FromMinutes(30);

        private HttpClient? _ownedHttpClient;

        /// <summary>A client that calls the API as an organisation's service account.</summary>
        /// <param name="token">The service account token, <c>ohrs_…</c>, from the portal's Service accounts page.</param>
        /// <param name="baseUrl">The API, if not <see cref="DefaultBaseUrl"/>.</param>
        /// <param name="innerHandler">The handler that sends requests (a proxy, a test double); a new <see cref="HttpClientHandler"/> by default.</param>
        public static OhrManagementClient ForServiceAccount(string token, Uri? baseUrl = null, HttpMessageHandler? innerHandler = null)
        {
            var http = new HttpClient(new OhrServiceTokenHandler(token) { InnerHandler = innerHandler ?? new HttpClientHandler() })
            {
                BaseAddress = WithSlash(baseUrl ?? DefaultBaseUrl),
                Timeout = RequestTimeout
            };
            return new OhrManagementClient(http) { _ownedHttpClient = http };
        }

        /// <summary>A client that calls the API as the person signed in to <paramref name="session"/>.</summary>
        /// <param name="innerHandler">The handler that sends requests; a new <see cref="HttpClientHandler"/> by default.</param>
        public static OhrManagementClient ForUser(OhrUserSession session, HttpMessageHandler? innerHandler = null)
        {
            if (session == null) throw new ArgumentNullException(nameof(session));
            var http = new HttpClient(new OhrUserSessionHandler(session) { InnerHandler = innerHandler ?? new HttpClientHandler() })
            {
                BaseAddress = session.BaseUrl,
                Timeout = RequestTimeout
            };
            return new OhrManagementClient(http) { _ownedHttpClient = http };
        }

        /// <summary>Disposes the HttpClient this client made for itself (not one passed to the constructor).</summary>
        public void Dispose()
        {
            _ownedHttpClient?.Dispose();
            _ownedHttpClient = null;
        }

        internal static Uri WithSlash(Uri u) => u.AbsoluteUri.EndsWith("/") ? u : new Uri(u.AbsoluteUri + "/");
    }
}
