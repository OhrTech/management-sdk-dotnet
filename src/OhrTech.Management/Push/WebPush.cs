#if NET10_0_OR_GREATER
using System;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace OhrTech.Management.Push;

/// <summary>
/// A web app's push subscription: what its page's <c>PushSubscription.toJSON()</c> gave your server. On an OhrTech
/// device the Push API runs on OhrTech push, so the subscription names the app's push token (its endpoint's last
/// part) and the token's public key, and your server's OhrTech sender key stands where a VAPID key would.
/// </summary>
/// <param name="Token">The app's push token (psh_…).</param>
/// <param name="Suite">The token's suite (<see cref="PushSuite"/>).</param>
/// <param name="PublicKey">The token's public key.</param>
public sealed record WebPushSubscription(string Token, string Suite, byte[] PublicKey)
{
    /// <summary>Where every OhrTech subscription's endpoint starts.</summary>
    public const string EndpointPrefix = "https://api.ohrtech.net/v1/web-push/";

    /// <summary>Reads a subscription's JSON. Throws <see cref="FormatException"/> for one that isn't OhrTech's.</summary>
    public static WebPushSubscription Parse(string json)
    {
        JsonNode? j;
        try
        {
            j = JsonNode.Parse(json);
        }
        catch (JsonException e)
        {
            throw new FormatException("the subscription isn't JSON: " + e.Message);
        }
        var endpoint = j?["endpoint"]?.GetValue<string>() ?? throw new FormatException("the subscription has no endpoint");
        if (!endpoint.StartsWith(EndpointPrefix, StringComparison.Ordinal))
            throw new FormatException($"{endpoint} isn't an OhrTech web app's subscription (an OhrTech device's start with {EndpointPrefix})");
        var token = endpoint[EndpointPrefix.Length..];
        var keys = j!["keys"] ?? throw new FormatException("the subscription has no keys");
        var suite = keys["suite"]?.GetValue<string>() ?? PushSuite.X25519;
        var key = keys["ohrtech"]?.GetValue<string>() ?? throw new FormatException("the subscription has no keys.ohrtech");
        var bytes = Base64Url(key);
        if (bytes.Length != PushSuite.PublicKeySize(suite))
            throw new FormatException($"keys.ohrtech isn't an {suite} public key");
        return new WebPushSubscription(token, suite, bytes);
    }

    private static byte[] Base64Url(string s)
    {
        var t = s.Replace('-', '+').Replace('_', '/');
        t += new string('=', (4 - t.Length % 4) % 4);
        try
        {
            return Convert.FromBase64String(t);
        }
        catch (FormatException)
        {
            throw new FormatException("keys.ohrtech isn't base64url");
        }
    }
}

/// <summary>
/// Declarative Web Push messages (<c>{"web_push": 8030, "notification": {...}}</c>): the device shows the notification
/// itself, with no service worker, and a tap opens <c>navigate</c> in the web app.
/// </summary>
public static class DeclarativeWebPush
{
    /// <summary>The message's bytes, for <see cref="PushSealer.SealForSubscription"/>.</summary>
    /// <param name="title">The notification's title.</param>
    /// <param name="navigate">The https page a tap opens (in the app's URL rules).</param>
    /// <param name="body">Its text.</param>
    /// <param name="tag">Replaces the app's notification of the same tag.</param>
    /// <param name="appBadge">The app's badge count, or null.</param>
    /// <param name="silent">No sound or vibration.</param>
    public static byte[] Create(string title, Uri navigate, string? body = null, string? tag = null, int? appBadge = null, bool silent = false)
    {
        if (navigate.Scheme != "https") throw new ArgumentException("navigate is an https URL", nameof(navigate));
        var n = new JsonObject { ["title"] = title, ["navigate"] = navigate.ToString() };
        if (body != null) n["body"] = body;
        if (tag != null) n["tag"] = tag;
        if (silent) n["silent"] = true;
        var m = new JsonObject { ["web_push"] = 8030, ["notification"] = n };
        if (appBadge != null) m["app_badge"] = appBadge.Value;
        return Encoding.UTF8.GetBytes(m.ToJsonString());
    }
}
#endif
