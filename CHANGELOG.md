# Changelog

## Unreleased

- Push (.NET 10): `PushSealer` seals and signs a message for an app's push token, end to end, in the token's
  suite: `x25519` (small, the default) or `xwing-mldsa65` (post-quantum: X-Wing and ML-DSA-65).
  `PushSenderKey` makes and loads your signing keys; give the app their public keys.
- Push API: `SendPushAsync` (up to 500 messages a call), `GetPushStatusAsync` and `ListPushTokensAsync`.
- Device SDK: `VerifyKeyAttestationAsync` checks that a key an app made was made in that device's TEE, for
  that app, bound to your challenge. `GetSdkAccessAsync`, `SetSdkAccessAsync` and `ClearSdkAccessAsync`
  set which Device SDK areas a fleet's app may use; `ListDeviceEventsAsync` lists what apps did with them.

## 2.1.0

- Privileged Android permissions by OhrTech approval: `ListAppPermissionsAsync` (each privileged permission an
  app's versions request: `granted`, `waiting` or `never`) and `ListOrgPermissionApprovalsAsync`; for OhrTech
  staff, `ApproveOrgPermissionAsync`, `WithdrawOrgPermissionAsync`, `ApproveAppPermissionAsync` and
  `WithdrawAppPermissionAsync`.

## 2.0.0

**Breaking:** ids are strings with a type prefix, such as `dev_01jftb4z0y9nn9yesabj71tyt0` (`dev_` a device, `flt_` a
fleet, `app_` an app, `org_` an organisation, `tsk_` a task, `usr_` a person, `sa_` a service account, `adb_` and
`rc_` sessions), where 1.x had numbers (and plain GUIDs for sessions). Organisations are `org`, not `client`:
`DeviceDto.OrgId` and `OrgName`, `MeDto.Orgs`, and the `orgId` filters.

- Apps: `ListAppsAsync`, `CreateAppAsync`, `GetAppAsync`, `UpdateAppAsync`, `ListAppVersionsAsync`,
  `SetAppVersionStateAsync`, `GetAppRolloutAsync`, and a fleet's apps (`ListFleetAppsAsync`, `AddFleetAppAsync`,
  `RemoveFleetAppAsync`).
- `UploadApkAsync(appId, path, state)` uploads an APK file as the app's new version. The API refuses an APK of another
  package, so a pipeline can't release the wrong app.
- App kinds: `ManagedAppDto.Kind` is `org` (your own app), `catalog` (provided by OhrTech, such as the Vanadium
  browser; add it to your fleets) or `platform` (part of the OS on every device, such as Vanadium System WebView).
  OhrTech releases catalog and platform versions; `OrgId` and `OrgName` are null for them. Versions carry `Notes` and
  `Security`.
- Fleet update control: `GetFleetAppPolicyAsync`, `SetFleetAppPolicyAsync` (automatic, or manual: only the version
  you approve, for as long as you like) and `ClearFleetAppPolicyAsync` for catalog and platform apps;
  `GetUpdateTimingAsync`, `SetUpdateTimingAsync`, `ClearUpdateTimingAsync`: when a fleet's devices install app updates
  (when the screen is off, in a maintenance window, either, or immediately).
- Rollouts report `held` (a manual fleet waits for approval) and `waiting` (downloaded, waiting for the fleet's update
  timing), and each device's `TargetVersionCode` and `Policy`.
- `WaitForRolloutAsync(appId)` waits until every online device the app applies to runs its version, waits for its
  fleet's update timing, is held, or failed; `untilInstalled: true` also waits for the timed installs.
- `OhrManagementJsonContext` is public: serialize the API types in trimmed and native AOT apps.
- The clients that `ForServiceAccount` and `ForUser` make allow 30 minutes per call (was 100 s), for large uploads.
  A person's client no longer copies large request bodies in memory to resend them after a 401.

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
