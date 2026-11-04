#:project ../src/OhrTech.Management/OhrTech.Management.csproj
// Runs the client where reflection-based JSON is off, as in .NET 10 file-based apps (this file is
// one), trimmed and native AOT apps. Every call goes to a canned handler, not the network.
//   dotnet run tests/no-reflection.cs
using System.Net;
using System.Text;
using System.Text.Json.Nodes;
using OhrTech.Management;

if (System.Text.Json.JsonSerializer.IsReflectionEnabledByDefault)
    throw new InvalidOperationException("This test must run with reflection-based serialization off.");

var sent = new List<string>();
using var api = OhrManagementClient.ForServiceAccount("ohrs_test", innerHandler: new Canned(sent));

var devices = await api.ListDevicesAsync(online: true);
Check(devices.Count == 1 && devices[0].DeviceId == "dev_01jftb4z0y9nn9yesabj71tyt0" && devices[0].OrgName == "Acme" && devices[0].BatteryLevel == 74, "ListDevices");

var device = await api.GetDeviceAsync("dev_01jftb4z0y9nn9yesabj71tyt0");
Check(device.Os.Fingerprint == "fp" && device.Capabilities.YourPermissions.Contains("ViewDevices"), "GetDevice");

await api.UpdateDeviceSettingsAsync("dev_01jftb4z0y9nn9yesabj71tyt0", new PolicyPatchDto
{
    Settings = new() { ["display.brightness"] = new SettingPolicy { Mode = SettingMode.Locked, Value = 80 } }
});
Check(sent[^1].Contains("\"mode\":\"Locked\"") && sent[^1].Contains("\"value\":80"), "UpdateDeviceSettings body");

await api.MoveDeviceAsync("dev_01jftb4z0y9nn9yesabj71tyt0", new MoveDeviceRequest { FleetId = null });
Check(sent[^1] == "{\"fleetId\":null}", "MoveDevice body keeps null");

var shell = await api.RunShellCommandAsync("dev_01jftb4z0y9nn9yesabj71tyt0", new RunShellCommandRequest { Command = "am start -a android.settings.SETTINGS", TimeoutSeconds = 30 });
Check(sent[^1].Contains("\"command\":\"am start -a android.settings.SETTINGS\"") && sent[^1].Contains("\"timeoutSeconds\":30"),
    "RunShellCommand body");
var done = await api.WaitForTaskAsync(shell);
Check(done.Status == "success" && done.Shell!.ExitCode == 0 && done.Shell.Stdout.StartsWith("Starting") && done.CreatedBy == "ops@example.com",
    "WaitForTask returns the finished task and its shell result");

var apk = Path.GetTempFileName();
await File.WriteAllBytesAsync(apk, [0x50, 0x4b, 0x03, 0x04]);
var version = await api.UploadApkAsync("app_01jftb4z0y9nn9yesabj71tyt0", apk, state: "enforced");
File.Delete(apk);
Check(version.VersionCode == 12 && version.State == "enforced" && sent[^1] == "PK\u0003\u0004",
    "UploadApk sends the file to the app");
var rollout = await api.WaitForRolloutAsync("app_01jftb4z0y9nn9yesabj71tyt0");
Check(rollout.UpToDate == 1 && rollout.Devices[0].Status == "up_to_date", "WaitForRollout returns once online devices are done");

try
{
    await api.GetDeviceAsync("dev_00000000000000000000000000");
    Check(false, "404 throws");
}
catch (OhrApiException<ProblemDetails> e)
{
    Check(e.StatusCode == 404 && e.Result.Title == "No such device", "ProblemDetails");
}

Console.WriteLine("OK: the client works with reflection-based serialization off.");

static void Check(bool ok, string what)
{
    if (!ok) throw new Exception($"FAILED: {what}");
    Console.WriteLine($"ok  {what}");
}

sealed class Canned(List<string> sent) : HttpMessageHandler
{
    int _taskPolls;
    int _rolloutPolls;

    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
    {
        if (request.Content != null) sent.Add(await request.Content.ReadAsStringAsync(ct));
        var path = request.RequestUri!.AbsolutePath;
        return path switch
        {
            "/v1/devices" => Json(HttpStatusCode.OK, """
                [{"deviceId":"dev_01jftb4z0y9nn9yesabj71tyt0","imei":"1","serial":"A0000A00042","orgId":"org_01jftb4z0y9nn9yesabj71tyt0","orgName":"Acme","online":true,
                  "remoteAdb":true,"typeName":"OhrTech Aleph","remoteControl":true,"batteryLevel":74,"charging":false,
                  "settingsErrors":0,"agentOutdated":false,"securityPatch":"2026-11-05","shellCommands":true}]
                """),
            "/v1/devices/dev_01jftb4z0y9nn9yesabj71tyt0" => Json(HttpStatusCode.OK, """
                {"deviceId":"dev_01jftb4z0y9nn9yesabj71tyt0","imei":"1","typeName":"OhrTech Aleph","orgId":"org_01jftb4z0y9nn9yesabj71tyt0","orgName":"Acme",
                 "createdAt":"2026-11-01T00:00:00Z","online":true,
                 "agent":{"version":1037,"outdated":false},"os":{"fingerprint":"fp"},"network":{},
                 "battery":{"charging":false},"settings":{"revision":"r1","errors":0},
                 "capabilities":{"remoteControl":true,"remoteAdb":true,"shellCommands":true,"yourPermissions":["ViewDevices"]}}
                """),
            "/v1/devices/dev_01jftb4z0y9nn9yesabj71tyt0/settings" => Json(HttpStatusCode.OK, """
                {"own":{},"inherited":{},"inheritedFrom":{},"effective":{},"revision":"r2"}
                """),
            "/v1/devices/dev_01jftb4z0y9nn9yesabj71tyt0/fleet" => new HttpResponseMessage(HttpStatusCode.NoContent),
            "/v1/apps/app_01jftb4z0y9nn9yesabj71tyt0/versions" when request.Method == HttpMethod.Post && request.RequestUri.Query == "?state=enforced" =>
                Json(HttpStatusCode.Created, """
                    {"appId":"app_01jftb4z0y9nn9yesabj71tyt0","packageName":"com.example.kiosk","versionCode":12,"versionName":"1.2","state":"enforced",
                     "signingKeySha256":"ab","permissions":[],"uploadedAt":"2026-11-04T00:00:00Z"}
                    """),
            "/v1/apps/app_01jftb4z0y9nn9yesabj71tyt0/rollout" => Json(HttpStatusCode.OK, ++_rolloutPolls < 2
                ? Rollout("installing", 0)
                : Rollout("up_to_date", 1)),
            "/v1/devices/dev_01jftb4z0y9nn9yesabj71tyt0/shell" => Json(HttpStatusCode.Created, Task("pending", null)),
            "/v1/devices/dev_01jftb4z0y9nn9yesabj71tyt0/tasks/tsk_01jftb4z0y9nn9yesabj71tyt0" => Json(HttpStatusCode.OK, ++_taskPolls < 2
                ? Task("running", null)
                : Task("success", """{"exitCode":0,"stdout":"Starting: Intent { act=android.settings.SETTINGS }\n","stderr":"","truncated":false,"timedOut":false,"durationMs":412}""")),
            _ => Json(HttpStatusCode.NotFound, """{"title":"No such device","status":404}""", "application/problem+json"),
        };
    }

    static string Task(string status, string? shell) => $$"""
        {"taskId":"tsk_01jftb4z0y9nn9yesabj71tyt0","deviceId":"dev_01jftb4z0y9nn9yesabj71tyt0","taskClass":"ExecuteShellCmd","parameters":["am start -a android.settings.SETTINGS","30"],
         "status":"{{status}}","priority":1000,"createdAt":"2026-11-03T17:00:00Z","modifiedAt":"2026-11-03T17:00:01Z",
         "messages":[],"createdBy":"ops@example.com","shell":{{shell ?? "null"}}}
        """;

    static string Rollout(string status, int upToDate) => $$"""
        {"appId":"app_01jftb4z0y9nn9yesabj71tyt0","packageName":"com.example.kiosk","targetVersionCode":12,"total":1,"upToDate":{{upToDate}},
         "held":0,"pending":0,"waiting":0,"installing":{{1 - upToDate}},"failed":0,
         "devices":[{"deviceId":"dev_01jftb4z0y9nn9yesabj71tyt0","online":true,"installedVersionCode":{{(upToDate == 1 ? 12 : 11)}},
                     "targetVersionCode":12,"policy":null,"status":"{{status}}"}]}
        """;

    static HttpResponseMessage Json(HttpStatusCode status, string body, string type = "application/json") =>
        new(status) { Content = new StringContent(body, Encoding.UTF8, type) };
}
