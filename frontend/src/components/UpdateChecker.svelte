<script lang="ts">
  import { onMount } from "svelte";
  import { check, type Update } from "@tauri-apps/plugin-updater";
  import { relaunch } from "@tauri-apps/plugin-process";
  import { commands, events } from "$lib/ipc/bindings";
  import { bytes } from "$lib/format";
  import { notices } from "$lib/notices.svelte";
  import { S } from "$lib/strings";

  let update = $state<Update | null>(null);
  let busy = $state(false);
  // Download progress, then the installing hint while the app restarts itself.
  let status = $state("");
  // The check answered: nothing newer than the running version.
  let fresh = $state(false);
  // A portable (tar.gz) install: the updater plugin would overwrite its binary with an AppImage
  // (selfupdate spec 1), so its update goes through the hub's own command.
  let portable = $state(false);

  onMount(() => {
    commands
      .runsAsAppimage()
      .then((fromImage) => (portable = !fromImage))
      .catch(() => {});
  });

  async function checkForUpdates(): Promise<void> {
    busy = true;
    update = null;
    fresh = false;
    status = "";
    try {
      update = (await check()) ?? null;
      fresh = update === null;
    } catch (err) {
      notices.push({ level: "Error", title: S.failed.updateCheck, text: String(err) });
    } finally {
      busy = false;
    }
  }

  async function installPortable(version: string): Promise<void> {
    const unlisten = await events.updateProgress.listen(({ payload }) => {
      const total = payload.total === null ? null : bytes(payload.total);
      status = S.download.progress(bytes(payload.received), total);
    });
    try {
      await commands.installPortableUpdate(version);
    } finally {
      unlisten();
    }
  }

  async function install(): Promise<void> {
    if (!update) return;
    busy = true;
    try {
      if (portable) {
        await installPortable(update.version);
      } else {
        let received = 0;
        let total: number | null = null;
        await update.downloadAndInstall((event) => {
          if (event.event === "Started") {
            total = event.data.contentLength ?? null;
          } else if (event.event === "Progress") {
            received += event.data.chunkLength;
            status = S.download.progress(bytes(received), total === null ? null : bytes(total));
          } else if (event.event === "Finished") {
            status = S.update.installing;
          }
        });
        await relaunch();
      }
    } catch (err) {
      notices.push({ level: "Error", title: S.failed.updateInstall, text: String(err) });
      busy = false;
    }
  }
</script>

{#if update}
  <p class="ok">{S.update.available(update.version)}</p>
  {#if status}<p class="muted">{status}</p>{/if}
  <div class="buttons">
    <button class="primary" disabled={busy} onclick={install}>{S.update.install}</button>
  </div>
{:else}
  {#if fresh}<p class="muted">{S.update.latest}</p>{/if}
  {#if status}<p class="muted">{status}</p>{/if}
  <div class="buttons">
    <button disabled={busy} onclick={checkForUpdates}>{S.update.check}</button>
  </div>
{/if}
