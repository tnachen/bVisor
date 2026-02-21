/**
 * Nested directory structures in a bVisor sandbox.
 *
 * Because the sandbox doesn't track state between commands, any operation
 * that needs to work inside a subdirectory must use `cd <dir> && <cmd>`.
 */
import { Sandbox } from "bvisor";

const sb = new Sandbox();

// Helper function to run a bash command and log its output streams.
async function run(cmd: string): Promise<void> {
  const output = sb.runCmd(cmd);
  const stdout = await output.stdout();
  const stderr = await output.stderr();
  console.log(`bvisor> ${cmd}`);
  if (stdout) console.log(stdout.trimEnd());
  if (stderr) console.error(stderr.trimEnd());
  console.log();
}

// Build a directory tree and populate it with files.
await run("mkdir -p project/src/assets");
await run("echo 'hello from root' > project/README.md");
await run("echo 'print(\"hello from src\")' > project/src/main.py");
await run("echo 'hello from assets' > project/src/assets/info.txt");

// Show the full tree.
await run("find project -type f");

// Run the script from its own directory.
// The sandbox starts at / each command, so we cd into the directory first.
await run("cd project/src && python3 main.py");

// Append to a file and verify.
await run("echo 'goodbye from assets' >> project/src/assets/info.txt");
await run("cat project/src/assets/info.txt");
