using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Threading;
using System.Threading.Tasks;

namespace OhrTech.Management
{
    /// <summary>Adds an organisation's service account token (<c>ohrs_…</c>) to every request.</summary>
    public sealed class OhrServiceTokenHandler : DelegatingHandler
    {
        private readonly string _token;

        public OhrServiceTokenHandler(string token)
        {
            if (string.IsNullOrWhiteSpace(token)) throw new ArgumentException("A service account token is required.", nameof(token));
            _token = token.Trim();
        }

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", _token);
            return base.SendAsync(request, cancellationToken);
        }
    }

    /// <summary>
    /// Adds a signed-in person's access token to every request, refreshing it shortly before it expires
    /// and once more if the API answers 401 (a token revoked early, a clock that is off).
    /// </summary>
    public sealed class OhrUserSessionHandler : DelegatingHandler
    {
        private readonly OhrUserSession _session;

        private const long RetryBufferLimit = 1024 * 1024;

        public OhrUserSessionHandler(OhrUserSession session) => _session = session ?? throw new ArgumentNullException(nameof(session));

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            // Kept so the request can be sent again: a request message can only be sent once. A large body
            // (an APK) is not copied: the token was fresh when it went, so a 401 for it is answered as is.
            var length = request.Content?.Headers.ContentLength;
            var body = request.Content == null || length is null or > RetryBufferLimit
                ? null
                : await request.Content.ReadAsByteArrayAsync().ConfigureAwait(false);
            var token = await _session.GetAccessTokenAsync(cancellationToken).ConfigureAwait(false);
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
            var response = await base.SendAsync(request, cancellationToken).ConfigureAwait(false);
            if (response.StatusCode != HttpStatusCode.Unauthorized || (request.Content != null && body == null)) return response;

            var fresh = await _session.RefreshAsync(token, cancellationToken).ConfigureAwait(false);
            if (fresh == token) return response;
            response.Dispose();
            var retry = new HttpRequestMessage(request.Method, request.RequestUri) { Version = request.Version };
            foreach (var h in request.Headers.Where(h => h.Key != "Authorization")) retry.Headers.TryAddWithoutValidation(h.Key, h.Value);
            if (body != null)
            {
                retry.Content = new ByteArrayContent(body);
                foreach (var h in request.Content!.Headers) retry.Content.Headers.TryAddWithoutValidation(h.Key, h.Value);
            }
            retry.Headers.Authorization = new AuthenticationHeaderValue("Bearer", fresh);
            return await base.SendAsync(retry, cancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>What to show the person signing in: open <see cref="VerificationUri"/> and enter <see cref="UserCode"/>.</summary>
    public sealed class OhrSignInPrompt
    {
        internal OhrSignInPrompt(DeviceLoginResponse r)
        {
            UserCode = r.UserCode;
            VerificationUri = new Uri(r.VerificationUri);
            VerificationUriComplete = new Uri(r.VerificationUriComplete);
            ExpiresAt = DateTimeOffset.UtcNow.AddSeconds(r.ExpiresIn);
        }

        /// <summary>The code to enter, such as BCDF-GHJK.</summary>
        public string UserCode { get; }

        /// <summary>The portal page where the person enters the code (https://portal.ohrtech.net/activate).</summary>
        public Uri VerificationUri { get; }

        /// <summary>The same page with the code filled in: open it in a browser, or show it as a QR code.</summary>
        public Uri VerificationUriComplete { get; }

        /// <summary>The code works until then.</summary>
        public DateTimeOffset ExpiresAt { get; }
    }

    /// <summary>Signing in did not finish: <see cref="Error"/> is access_denied (the person declined) or expired_token (the code ran out).</summary>
    public sealed class OhrSignInException : Exception
    {
        public OhrSignInException(string error, string message) : base(message) => Error = error;

        public string Error { get; }
    }

    /// <summary>
    /// A person signed in to the OhrTech Management API. The access token lives an hour and is refreshed as needed;
    /// the refresh token lives 30 days from its last use. Keep <see cref="RefreshToken"/> (it is a
    /// password-grade secret) to resume later with <see cref="Resume"/>, and save it again whenever
    /// <see cref="TokensRefreshed"/> fires. Signing out everywhere in the portal, or a password change,
    /// ends the session: calls then fail with 401.
    /// </summary>
    public sealed partial class OhrUserSession
    {
        private static readonly TimeSpan RefreshAhead = TimeSpan.FromMinutes(1);
        private readonly SemaphoreSlim _refreshing = new SemaphoreSlim(1, 1);
        private readonly HttpMessageHandler? _innerHandler;

        private OhrUserSession(Uri baseUrl, string? accessToken, DateTimeOffset expiresAt, string refreshToken, HttpMessageHandler? innerHandler)
        {
            BaseUrl = OhrManagementClient.WithSlash(baseUrl);
            AccessToken = accessToken;
            AccessTokenExpiresAt = expiresAt;
            RefreshToken = refreshToken;
            _innerHandler = innerHandler;
        }

        public Uri BaseUrl { get; }

        /// <summary>The current access token, or null before the first call of a resumed session.</summary>
        public string? AccessToken { get; private set; }

        public DateTimeOffset AccessTokenExpiresAt { get; private set; }

        public string RefreshToken { get; private set; }

        /// <summary>New tokens were issued. Save <see cref="RefreshToken"/> if you keep the session between runs.</summary>
        public event EventHandler? TokensRefreshed;

        /// <summary>Resumes a session from a saved refresh token; the first call gets a fresh access token.</summary>
        public static OhrUserSession Resume(string refreshToken, Uri? baseUrl = null, HttpMessageHandler? innerHandler = null)
        {
            if (string.IsNullOrWhiteSpace(refreshToken)) throw new ArgumentException("A refresh token is required.", nameof(refreshToken));
            return new OhrUserSession(baseUrl ?? OhrManagementClient.DefaultBaseUrl, null, DateTimeOffset.MinValue, refreshToken, innerHandler);
        }

        /// <summary>
        /// Signs a person in with the device authorization flow (RFC 8628): <paramref name="prompt"/> is
        /// called once with the code to show them; they open the link, sign in to the portal as usual
        /// (password and two-factor, or Microsoft) and approve. Returns when they have.
        /// </summary>
        /// <param name="prompt">Shows the person the code and link.</param>
        /// <param name="clientName">How the portal names this sign-in when asking the person to approve it.</param>
        /// <exception cref="OhrSignInException">The person declined, or the code expired.</exception>
        public static async Task<OhrUserSession> SignInAsync(Action<OhrSignInPrompt> prompt, string clientName = "OhrTech.Management",
            Uri? baseUrl = null, HttpMessageHandler? innerHandler = null, CancellationToken cancellationToken = default)
        {
            if (prompt == null) throw new ArgumentNullException(nameof(prompt));
            baseUrl = OhrManagementClient.WithSlash(baseUrl ?? OhrManagementClient.DefaultBaseUrl);
            using var http = Anonymous(baseUrl, innerHandler);
            var api = new OhrManagementClient(http);

            var start = await api.StartDeviceLoginAsync(new DeviceLoginRequest { ClientName = clientName }, cancellationToken).ConfigureAwait(false);
            prompt(new OhrSignInPrompt(start));
            var interval = TimeSpan.FromSeconds(Math.Max(start.Interval, 1));
            var deadline = DateTimeOffset.UtcNow.AddSeconds(start.ExpiresIn);
            while (true)
            {
                await Task.Delay(interval, cancellationToken).ConfigureAwait(false);
                try
                {
                    var t = await api.PollDeviceLoginAsync(new DeviceTokenRequest { DeviceCode = start.DeviceCode }, cancellationToken)
                        .ConfigureAwait(false);
                    return new OhrUserSession(baseUrl, t.AccessToken, DateTimeOffset.UtcNow.AddSeconds(t.ExpiresIn), t.RefreshToken, innerHandler);
                }
                catch (OhrApiException<TokenError> e)
                {
                    switch (e.Result.Error)
                    {
                        case "authorization_pending" when DateTimeOffset.UtcNow < deadline:
                            continue;
                        case "slow_down":
                            interval += TimeSpan.FromSeconds(5);
                            continue;
                        case "access_denied":
                            throw new OhrSignInException(e.Result.Error, "The sign-in was declined in the portal.");
                        default:
                            throw new OhrSignInException("expired_token", "The sign-in code expired before it was approved. Start again.");
                    }
                }
            }
        }

        /// <summary>A valid access token, refreshed first if it expires within a minute.</summary>
        public async Task<string> GetAccessTokenAsync(CancellationToken cancellationToken = default)
        {
            var token = AccessToken;
            if (token != null && DateTimeOffset.UtcNow < AccessTokenExpiresAt - RefreshAhead) return token;
            return await RefreshAsync(token, cancellationToken).ConfigureAwait(false);
        }

        /// <summary>
        /// Trades the refresh token for new tokens, unless another call already replaced <paramref name="stale"/>.
        /// Throws <see cref="OhrApiException"/> (401) when the session has ended: sign in again.
        /// </summary>
        internal async Task<string> RefreshAsync(string? stale, CancellationToken cancellationToken)
        {
            await _refreshing.WaitAsync(cancellationToken).ConfigureAwait(false);
            try
            {
                if (AccessToken != null && AccessToken != stale && DateTimeOffset.UtcNow < AccessTokenExpiresAt - RefreshAhead)
                    return AccessToken;
                using var http = Anonymous(BaseUrl, _innerHandler);
                var t = await new OhrManagementClient(http).RefreshLoginAsync(new RefreshRequest { RefreshToken = RefreshToken }, cancellationToken)
                    .ConfigureAwait(false);
                AccessToken = t.AccessToken;
                AccessTokenExpiresAt = DateTimeOffset.UtcNow.AddSeconds(t.ExpiresIn);
                RefreshToken = t.RefreshToken;
                TokensRefreshed?.Invoke(this, EventArgs.Empty);
                return t.AccessToken;
            }
            finally
            {
                _refreshing.Release();
            }
        }

        // The sign-in calls take no token. A caller's handler is shared, so it must not be disposed with this client.
        private static HttpClient Anonymous(Uri baseUrl, HttpMessageHandler? innerHandler) =>
            innerHandler == null
                ? new HttpClient { BaseAddress = baseUrl }
                : new HttpClient(innerHandler, disposeHandler: false) { BaseAddress = baseUrl };
    }
}
