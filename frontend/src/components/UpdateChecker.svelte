<script lang="ts">
  import { check, type Update } from "@tauri-apps/plugin-updater";
  import { relaunch } from "@tauri-apps/plugin-process";
  import { bytes } from "$lib/format";
  import { notices } from "$lib/notices.svelte";
  import { S } from "$lib/strings";

  let update = $state<Update | null>(null);
  let busy = $state(false);
  // Download progress, then the installing hint while the app restarts itself.
  let status = $state("");
  // The check answered: nothing newer than the running version.
  let fresh = $state(false);

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

  async function install(): Promise<void> {
    if (!update) return;
    busy = true;
    try {
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
