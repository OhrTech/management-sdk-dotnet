using System;
using System.Threading;
using System.Threading.Tasks;

namespace OhrTech.Management
{
    public partial class OhrManagementClient
    {
        /// <summary>
        /// Waits until the device has finished <paramref name="task"/> (status <c>success</c>, <c>failed</c> or
        /// <c>cancelled</c>) and returns it as it is then, with what the device reported, such as a shell
        /// command's output in <see cref="TaskDto.Shell"/>. It asks the API once a second (and less often after a minute).
        /// </summary>
        /// <param name="task">A task, as returned when it was created (for example by <c>RunShellCommandAsync</c>).</param>
        /// <param name="timeout">How long to wait; 5 minutes by default. Then it throws <see cref="TimeoutException"/>,
        /// and the task carries on: an offline device runs it when it next connects.</param>
        public async Task<TaskDto> WaitForTaskAsync(TaskDto task, TimeSpan? timeout = null, CancellationToken cancellationToken = default)
        {
            if (task == null) throw new ArgumentNullException(nameof(task));
            var deadline = DateTime.UtcNow + (timeout ?? TimeSpan.FromMinutes(5));
            var started = DateTime.UtcNow;
            while (!IsFinished(task.Status))
            {
                var wait = DateTime.UtcNow - started < TimeSpan.FromMinutes(1) ? TimeSpan.FromSeconds(1) : TimeSpan.FromSeconds(5);
                if (DateTime.UtcNow + wait > deadline)
                    throw new TimeoutException($"Task {task.TaskId} on device {task.DeviceId} is still {task.Status}.");
                await Task.Delay(wait, cancellationToken).ConfigureAwait(false);
                task = await GetTaskAsync(task.DeviceId, task.TaskId, cancellationToken).ConfigureAwait(false);
            }
            return task;
        }

        private static bool IsFinished(string status) => status == "success" || status == "failed" || status == "cancelled";
    }
}
