# OhrTech.Management

The .NET client for the [OhrTech Management API](https://github.com/OhrTech/management-api): manage
your organisation's devices from your own servers and tools. Device status and settings, fleets,
messages and tasks, remote control (with a viewer you can embed in your web app) and remote ADB.

```sh
dotnet add package OhrTech.Management
```

`netstandard2.0` and `net10.0`, with no reflection-based serialization, so it also works in .NET 10
file-based apps (`dotnet run script.cs`), trimmed and native AOT apps. This is the **Management** SDK, for servers and desktop tools. Apps
running *on* a managed device will use the Device SDK (`device-sdk-*`, coming later) to talk to the
OhrTech Agent instead.

## Sign in

**As a service account**, for servers and automation. Create the account and its token in the
[portal](https://portal.ohrtech.net) under Service accounts, grant it only the permissions it needs
(ViewDevices, EditSettings, SendMessages, RemoteControl, …), and limit it to the fleets or devices,
networks and embed sites it works with.

```csharp
using OhrTech.Management;

using var api = OhrManagementClient.ForServiceAccount(Environment.GetEnvironmentVariable("OHR_TOKEN")!);
```

**As a person**, for tools people run. They approve the sign-in in the portal with their usual
login; the client refreshes their access token for you.

```csharp
var session = await OhrUserSession.SignInAsync(p =>
    Console.WriteLine($"Open {p.VerificationUri} and enter {p.UserCode}"));
using var api = OhrManagementClient.ForUser(session);

// Keep session.RefreshToken (a secret) to skip signing in next time:
//   OhrUserSession.Resume(savedRefreshToken); save it again on session.TokensRefreshed.
```

**As whoever is signed in to the `ohr` CLI**, for quick scripts and development on your own
machine. It reads the CLI's saved login (`ohr login`) and never changes it:

```csharp
using var api = OhrManagementClient.ForUser(OhrUserSession.FromOhrCli());
```

**With IHttpClientFactory:** add `OhrServiceTokenHandler` or `OhrUserSessionHandler` to your
`HttpClient`, set its `BaseAddress` to `OhrManagementClient.DefaultBaseUrl`, and use
`new OhrManagementClient(httpClient)`.

## Use it

Every API operation is a method (`IOhrManagementClient`), named after its operation id in the
[reference](https://api.ohrtech.net/docs).

```csharp
foreach (var d in await api.ListDevicesAsync(online: true))
    Console.WriteLine($"{d.DeviceId} {d.Serial} {d.FleetName} battery {d.BatteryLevel}%");

var device = await api.GetDeviceAsync(42);
await api.ShowMessageAsync(42, new ShowMessageRequest { Text = "Please plug me in" });
await api.UpdateDeviceSettingsAsync(42, new PolicyPatchDto
{
    Settings = new() { ["display.brightness"] = new SettingPolicy { Mode = SettingMode.Locked, Value = 80 } }
});
```

Errors are `OhrApiException<ProblemDetails>` (or `OhrApiException<HttpValidationProblemDetails>`
for invalid settings): `e.StatusCode`, `e.Result.Title`, `e.Result.Detail`.

## Remote control in your web app

```csharp
var rc = await api.OpenRemoteControlSessionAsync(42, new OpenRemoteControlRequest
{
    EmbedOrigins = new() { "https://support.example.com" }
});
// Hand rc.Embed.Url to your page (it is a credential until rc.Embed.ExpiresAt):
// <iframe src="{rc.Embed.Url}" allow="fullscreen; clipboard-read" style="width:100%;height:720px"></iframe>
```

The viewer reports its state to your page with `postMessage` and takes `key`, `text`, `refresh`,
`focus` and `end` commands back: see
[embedding.md](https://github.com/OhrTech/management-api/blob/main/embedding.md).

## Developing

`src/OhrTech.Management/Generated/` is generated from `openapi.json` by `./generate.sh` (NSwag, a
repo-local tool); don't edit it by hand. To pick up a new API version:

```sh
./generate.sh https://raw.githubusercontent.com/OhrTech/management-api/main/openapi.json
dotnet build -c Release
```

`tests/no-reflection.cs` checks the client with reflection-based JSON off:
`dotnet run --no-cache tests/no-reflection.cs`.

Releases: push a `v*` tag (such as `v1.0.1`) and GitHub Actions packs it with that version and
publishes it to nuget.org.

## License

[MIT](LICENSE)
