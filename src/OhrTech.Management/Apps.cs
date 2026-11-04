using System;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

namespace OhrTech.Management
{
    public partial class OhrManagementClient
    {
        /// <summary>
        /// Uploads an APK file as the app's new version (POST /v1/apps/{appId}/versions). The API refuses an APK of
        /// another package ("Wrong app"), a version code that isn't newer, or a different signing key.
        /// </summary>
        /// <param name="appId">The app (app_…): <see cref="ListAppsAsync"/> lists the apps with a package name, <see cref="CreateAppAsync"/> adds one.</param>
        /// <param name="apkPath">The .apk file: a single, signed APK, not an .aab.</param>
        /// <param name="state"><c>held</c> (devices don't get it), <c>available</c> (offered to the device's own app) or
        /// <c>enforced</c> (every device in the app's fleets installs it).</param>
        /// <param name="allowNewSigningKey">Accept a signing key that differs from the previous version's (a v3 key rotation).</param>
        public async Task<AppVersionDto> UploadApkAsync(string appId, string apkPath, string state = "held", bool allowNewSigningKey = false,
            CancellationToken cancellationToken = default)
        {
            using var file = new FileStream(apkPath, FileMode.Open, FileAccess.Read, FileShare.Read, 1 << 16, useAsync: true);
            return await UploadApkAsync(appId, file, state, allowNewSigningKey ? true : null, cancellationToken).ConfigureAwait(false);
        }

        /// <summary>
        /// Waits until every online device the app applies to has done what it can (GET /v1/apps/{appId}/rollout every
        /// 5 seconds), and returns the rollout then: it runs its target version (up_to_date), downloaded it and waits for
        /// its fleet's update timing such as the screen to be off (waiting), is on a Manual fleet that hasn't approved the
        /// version (held), or failed. Offline devices don't hold it up: they install the version when they next connect.
        /// </summary>
        /// <param name="timeout">How long to wait; 15 minutes by default. Then it throws <see cref="TimeoutException"/>.</param>
        /// <param name="untilInstalled">Also wait for the devices that wait for their fleet's update timing to install it.</param>
        public async Task<RolloutDto> WaitForRolloutAsync(string appId, TimeSpan? timeout = null, bool untilInstalled = false,
            CancellationToken cancellationToken = default)
        {
            var deadline = DateTime.UtcNow + (timeout ?? TimeSpan.FromMinutes(15));
            while (true)
            {
                var rollout = await GetAppRolloutAsync(appId, cancellationToken).ConfigureAwait(false);
                if (rollout.Devices.All(d => !d.Online || d.Status is "up_to_date" or "held" or "failed" ||
                                             (!untilInstalled && d.Status == "waiting")))
                    return rollout;
                if (DateTime.UtcNow + TimeSpan.FromSeconds(5) > deadline)
                    throw new TimeoutException($"App {appId}: {rollout.Pending + rollout.Installing + (untilInstalled ? rollout.Waiting : 0)} " +
                                               $"device(s) still getting version {rollout.TargetVersionCode}.");
                await Task.Delay(TimeSpan.FromSeconds(5), cancellationToken).ConfigureAwait(false);
            }
        }
    }
}
