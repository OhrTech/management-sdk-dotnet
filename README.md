# OhrTech.Management

The .NET client for the [OhrTech Management API](https://docs.ohrtech.net/management-api/): manage
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
[reference](https://api.ohrtech.net/docs). Everything is named by a string id with a type prefix:
`dev_…` a device, `flt_…` a fleet, `app_…` an app, `org_…` an organisation, `tsk_…` a task.

```csharp
foreach (var d in await api.ListDevicesAsync(online: true))
    Console.WriteLine($"{d.DeviceId} {d.Serial} {d.FleetName} battery {d.BatteryLevel}%");

var device = await api.GetDeviceAsync("dev_01jftb4z0y9nn9yesabj71tyt0");
await api.ShowMessageAsync("dev_01jftb4z0y9nn9yesabj71tyt0", new ShowMessageRequest { Text = "Please plug me in" });
await api.UpdateDeviceSettingsAsync("dev_01jftb4z0y9nn9yesabj71tyt0", new PolicyPatchDto
{
    Settings = new() { ["display.brightness"] = new SettingPolicy { Mode = SettingMode.Locked, Value = 80 } }
});
```

Errors are `OhrApiException<ProblemDetails>` (or `OhrApiException<HttpValidationProblemDetails>`
for invalid settings): `e.StatusCode`, `e.Result.Title`, `e.Result.Detail`.

## Release your app

```csharp
// The app's id: ListAppsAsync(package: …) lists the apps with a package (flavours for different fleets may share one).
var version = await api.UploadApkAsync("app_01jftb4z0y9nn9yesabj71tyt0", "app-release.apk", state: "enforced");
var rollout = await api.WaitForRolloutAsync("app_01jftb4z0y9nn9yesabj71tyt0"); // every online device runs it, or failed
```

The API refuses an APK of another package than the app's, a version code that isn't newer, and a
different signing key. From a build pipeline, the [`ohr` command line](https://github.com/OhrTech/ohr-cli)
does the same in one step.

## Device attestation (.NET 10)

Your app attests a key with the Device SDK (`sdk.attestation.attest(challenge)`) and sends the
result once; your server checks it and keeps the key, then checks each request's token. Offline,
against the OhrTech Attestation Root built into the SDK:

```csharp
using OhrTech.Management.Attestation;

var status = await AttestationStatusList.FetchAsync(http);   // the revoked devices, signed; refresh a few times a day
var verifier = new DeviceAttestationVerifier(new DeviceAttestationPolicy { PackageName = "com.example.pos", MinOsPatchLevel = 202610 });
var result = verifier.Verify(attestationJson, challenge, status);
if (!result.Accepted) return Forbid(result.Reason ?? string.Join("; ", result.Problems));
Save(result.DeviceId, result.EcPublicKey, result.MlDsa65PublicKey);   // MlDsa65PublicKey: the post-quantum suite

// Each request: the token the app made with sdk.attestation.token("https://api.example.com").
var claims = AttestationToken.Verify(token, "https://api.example.com", ecPublicKey, mlDsa65PublicKey);
```

`Accepted` means the chain runs to the OhrTech root through a unit that names itself (`dev_…`), the
key is in the TEE and bound to your challenge, the device isn't revoked, and the policy holds:
verified boot, a locked bootloader, OhrTech's boot key, then your package, signer and patch level.
Online, `VerifyAttestationAsync` checks the same and, for your own devices, names the fleet and the
app as well. `RevokeDeviceAttestationAsync` revokes a lost or retired device's keys.

## Remote control in your web app

```csharp
var rc = await api.OpenRemoteControlSessionAsync("dev_01jftb4z0y9nn9yesabj71tyt0", new OpenRemoteControlRequest
{
    EmbedOrigins = new() { "https://support.example.com" }
});
// Hand rc.Embed.Url to your page (it is a credential until rc.Embed.ExpiresAt):
// <iframe src="{rc.Embed.Url}" allow="fullscreen; clipboard-read" style="width:100%;height:720px"></iframe>
```

The viewer reports its state to your page with `postMessage` and takes `key`, `text`, `refresh`,
`focus` and `end` commands back: see
[Embed remote control](https://docs.ohrtech.net/management-api/guides/embed-remote-control/).

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
