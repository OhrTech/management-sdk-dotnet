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
Check(devices.Count == 1 && devices[0].Serial == "A0316A40462" && devices[0].BatteryLevel == 74, "ListDevices");

var device = await api.GetDeviceAsync(6);
Check(device.Os.Fingerprint == "fp" && device.Capabilities.YourPermissions.Contains("ViewDevices"), "GetDevice");

await api.UpdateDeviceSettingsAsync(6, new PolicyPatchDto
{
    Settings = new() { ["display.brightness"] = new SettingPolicy { Mode = SettingMode.Locked, Value = 80 } }
});
Check(sent[^1].Contains("\"mode\":\"Locked\"") && sent[^1].Contains("\"value\":80"), "UpdateDeviceSettings body");

await api.MoveDeviceAsync(6, new MoveDeviceRequest { FleetId = null });
Check(sent[^1] == "{\"fleetId\":null}", "MoveDevice body keeps null");

try
{
    await api.GetDeviceAsync(404);
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
    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
    {
        if (request.Content != null) sent.Add(await request.Content.ReadAsStringAsync(ct));
        var path = request.RequestUri!.AbsolutePath;
        return path switch
        {
            "/v1/devices" => Json(HttpStatusCode.OK, """
                [{"deviceId":6,"imei":"1","serial":"A0316A40462","clientId":1,"clientName":"Acme","online":true,
                  "remoteAdb":true,"typeName":"OhrTech Aleph","remoteControl":true,"batteryLevel":74,"charging":false,
                  "settingsErrors":0,"agentOutdated":false}]
                """),
            "/v1/devices/6" => Json(HttpStatusCode.OK, """
                {"deviceId":6,"imei":"1","typeName":"OhrTech Aleph","clientId":1,"clientName":"Acme",
                 "createdAt":"2026-11-01T00:00:00Z","online":true,
                 "agent":{"version":1037,"outdated":false},"os":{"fingerprint":"fp"},"network":{},
                 "battery":{"charging":false},"settings":{"revision":"r1","errors":0},
                 "capabilities":{"remoteControl":true,"remoteAdb":true,"yourPermissions":["ViewDevices"]}}
                """),
            "/v1/devices/6/settings" => Json(HttpStatusCode.OK, """
                {"own":{},"inherited":{},"inheritedFrom":{},"effective":{},"revision":"r2"}
                """),
            "/v1/devices/6/fleet" => new HttpResponseMessage(HttpStatusCode.NoContent),
            _ => Json(HttpStatusCode.NotFound, """{"title":"No such device","status":404}""", "application/problem+json"),
        };
    }

    static HttpResponseMessage Json(HttpStatusCode status, string body, string type = "application/json") =>
        new(status) { Content = new StringContent(body, Encoding.UTF8, type) };
}
