<script lang="ts">
  import { onMount } from "svelte";
  import { commands } from "$lib/ipc/bindings";
  import { S } from "$lib/strings";

  interface Props {
    /** What the field holds now: the names already there are not offered again. */
    current: string;
    /** A chip's click: the name joins the field on its own line. */
    add: (name: string) => void;
  }

  let { current, add }: Props = $props();

  let apps = $state<string[] | null>(null);

  const present = $derived(
    new Set(
      current
        .split(/\r?\n/)
        .map((line) => line.trim().toLowerCase())
        .filter(Boolean),
    ),
  );
  const offered = $derived((apps ?? []).filter((name) => !present.has(name.toLowerCase())));

  onMount(() => {
    // A plain list, not an `Answer`: an empty one on failure is what the chips need.
    commands
      .runningApps()
      .then((list) => (apps = list))
      .catch(() => (apps = []));
  });
</script>

{#if offered.length > 0}
  <div class="running">
    <span class="muted hint">{S.routes.exclusions.running}</span>
    <div class="chips">
      {#each offered as name (name)}
        <button onclick={() => add(name)}>+ {name}</button>
      {/each}
    </div>
  </div>
{/if}

<style>
  .running {
    display: flex;
    flex-direction: column;
    gap: 4px;
  }
  .chips {
    display: flex;
    flex-wrap: wrap;
    gap: 6px;
  }
  .chips button {
    height: 24px;
    line-height: 1;
    font-size: 12px;
    padding: 0 8px;
  }
</style>
