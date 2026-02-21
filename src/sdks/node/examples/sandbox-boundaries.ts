/**
 * Testing the safety of sandboxes in bVisor. 
 *
 * Three classic escape/peeking attempts fail in bVisor:
 *   1. Host fingerprinting: system identity is virtualized
 *   2. Blocked paths: hardware and system metadata are inaccessible
 *   3. Persistent writes: file modifications are isolated per-sandbox
 */
import { Sandbox } from "bvisor";

async function run(sb: Sandbox, cmd: string): Promise<void> {
  const output = sb.runCmd(cmd);
  const stdout = await output.stdout();
  const stderr = await output.stderr();
  console.log(`bvisor> ${cmd}`);
  if (stdout) console.log(stdout.trimEnd());
  if (stderr) console.error(stderr.trimEnd());
  console.log();
}

const sb = new Sandbox();

// === Attempt 1: Host fingerprinting ===
// An agent tries to discover which machine it's running on.
// uname(2) is intercepted: nodename is replaced with "bvisor"
// and domainname is cleared — the real hostname never leaks.
console.log("--- Attempt 1: Host fingerprinting ---");
await run(sb, "uname -n");  // → "bvisor" (not the real hostname)
await run(sb, "uname -a");  // real kernel/arch, but nodename is "bvisor"

// === Attempt 2: Blocked system paths ===
// An agent tries to enumerate network interfaces, read a block device,
// or access runtime sockets to learn about the host environment.
// /sys, /dev/* (except null/zero/random), and /run are hard-blocked with EPERM.
console.log("--- Attempt 2: Blocked system paths ---");
await run(sb, "ls /sys/class/net");  // → Permission denied
await run(sb, "cat /dev/sda");       // → Permission denied
await run(sb, "ls /run");            // → Permission denied

// === Attempt 3: Persistent backdoor ===
// An agent appends a malicious entry to /etc/hosts, trying to redirect
// traffic or leave a persistent foothold. The write succeeds inside the
// sandbox (via the COW overlay) but is invisible to any other sandbox —
// each sandbox gets its own isolated copy-on-write layer.
console.log("--- Attempt 3: Persistent backdoor attempt ---");
const sb1 = new Sandbox();
const sb2 = new Sandbox();

// "Agent" appends to /etc/hosts inside sb1
await run(sb1, "echo '1.2.3.4 c2.example.com' >> /etc/hosts");
// The change is visible within sb1's own overlay
await run(sb1, "grep c2 /etc/hosts");

// A second sandbox reads the same file — it sees the original, unmodified hosts
await run(sb2, "grep c2 /etc/hosts || echo '(not found — original file intact)'");