# Changelog

## 1.1.0

- `RunShellCommandAsync`: run a shell command on a device, as `adb shell` would. It needs the
  `RemoteAdb` permission. The finished task's `Shell` holds the exit code, stdout and stderr.
- `WaitForTaskAsync`: wait until the device has finished a task, then return it.
- `TaskDto.CreatedBy`: who created a task (a person's email or a service account).
- `DeviceDto.SecurityPatch` and `OsDto.SecurityPatch`: the Android security patch level the device
  runs now, as YYYY-MM-DD.
- `CapabilitiesDto.ShellCommands` and `DeviceDto.ShellCommands`: whether a device can run shell commands.

## 1.0.1

- Works where reflection-based JSON is off: .NET 10 file-based apps (`dotnet run app.cs`), trimmed
  and native AOT apps. 1.0.0 failed there on the first call with "Reflection-based serialization
  has been disabled". The client now uses source-generated JSON metadata and is marked AOT compatible.
- `OpenRemoteControlRequest.TakeOver` is `bool?`: the API treats it as optional.

## 1.0.0

First release, for Management API v1.
