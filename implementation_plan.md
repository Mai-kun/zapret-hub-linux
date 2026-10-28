# Implementation Plan: Process-based Exclusions in Zapret-Hub

## 1. Model Updates (Data & DTOs)
- Edit `src-tauri/src/dto.rs`:
    - Add `apps: Vec<String>` to `Exclusions` struct with `#[serde(default)]`.
- Edit `crates/router/src/rules.rs`:
    - Verify `Rule` struct already has `apps`.
    - Ensure `exclusions.toml` (which seems to be `routes.toml` or similar) is handled correctly by adding the `apps` field if missing. Wait, looking at `rules.rs`, it already has `apps`. I will verify if `data/exclusions.toml` exists or if the routes system handles exclusions. *Self-correction: I should check where `read_exclusions` gets its lists.*

## 2. Kernel & Networking (NFTables/Cgroups)
- Modify `crates/zapret2/src/nft.rs`:
    - Implement `ensure_cgroup()` to create `/sys/fs/cgroup/zapret_bypass`.
    - Update `table()` function to include:
        - `socket cgroupv2 level 1 "zapret_bypass" return`
        - `set bypass_tcp_ports { type inet_service; }`
        - `set bypass_udp_ports { type inet_service; }`
        - Rules: `tcp sport @bypass_tcp_ports return` and `udp sport @bypass_udp_ports return`.

## 3. Background Monitor (src-tauri)
- Create `src-tauri/src/monitor.rs` (or add to `actions.rs`):
    - Implement a loop that runs every 1–2 seconds.
    - Logic:
        - Read active `apps` from configuration.
        - Scan `/proc` for processes matching `apps`.
        - Add PIDs to `/sys/fs/cgroup/zapret_bypass/cgroup.procs`.
        - Scan `/proc/[pid]/fd` and `/proc/net/{tcp,udp}` to find open ports.
        - Update nftables sets using `nft add element inet zapret_hub bypass_tcp_ports { <port> }`.

## 4. Frontend (UI)
- Update `frontend/src/tabs/Routes.svelte`:
    - Add "Программы" input field in the exclusion editor.
    - Update the UI to show and edit these lists.

## 5. CLI Updates
- Update `crates/cli/src/main.rs`:
    - Add `apps` subcommands (`add`/`remove`) for exclusions.

---

### Verification
- `cargo test --workspace`
- `npm run check`
- Live test with `opencode` process monitoring.
