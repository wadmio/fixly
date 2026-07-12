// Desktop + webhook notifications for the daemon — zero added dependencies.
// Desktop notifications shell out to the OS notifier (PowerShell toast on
// Windows, osascript on macOS, notify-send on Linux) and are strictly
// best-effort: any failure degrades silently to terminal-only output.

import { spawn } from "node:child_process";
import { fetchWithRetry } from "@fixly/core";

function fireAndForget(command: string, args: string[]): void {
  try {
    const child = spawn(command, args, { stdio: "ignore" });
    child.on("error", () => {});
    child.unref();
  } catch {
    // best-effort
  }
}

export function notifyDesktop(title: string, body: string): void {
  // Apostrophes would close the single-quoted shell/PS strings below.
  const t = title.replace(/'/g, "’");
  const b = body.replace(/'/g, "’");
  if (process.platform === "win32") {
    const script = [
      "$null = [Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime]",
      "$tpl = [Windows.UI.Notifications.ToastNotificationManager]::GetTemplateContent([Windows.UI.Notifications.ToastTemplateType]::ToastText02)",
      "$nodes = $tpl.GetElementsByTagName('text')",
      `$null = $nodes.Item(0).AppendChild($tpl.CreateTextNode('${t}'))`,
      `$null = $nodes.Item(1).AppendChild($tpl.CreateTextNode('${b}'))`,
      "$toast = [Windows.UI.Notifications.ToastNotification]::new($tpl)",
      "[Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier('fixly').Show($toast)",
    ].join("; ");
    fireAndForget("powershell", ["-NoProfile", "-NonInteractive", "-Command", script]);
  } else if (process.platform === "darwin") {
    fireAndForget("osascript", [
      "-e",
      `display notification "${b.replace(/"/g, '\\"')}" with title "${t.replace(/"/g, '\\"')}"`,
    ]);
  } else {
    fireAndForget("notify-send", ["--app-name=fixly", t, b]);
  }
}

/** POST a JSON event; returns whether delivery succeeded. Never throws. */
export async function sendWebhook(url: string, payload: unknown): Promise<boolean> {
  try {
    const res = await fetchWithRetry(
      url,
      {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      },
      { retries: 1, timeoutMs: 5_000 }
    );
    return res.ok;
  } catch {
    return false;
  }
}
