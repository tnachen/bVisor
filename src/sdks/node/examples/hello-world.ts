/**
 * Hello World!
 *
 * How to run a command in a bVisor sandbox.
 */
import { Sandbox } from "bvisor";

// Create the sandbox
const sb = new Sandbox();

// Start the bash command
const output = sb.runCmd("echo 'Hello from bVisor!'");

// Await the output streams
const stdout = await output.stdout();
const stderr = await output.stderr();

console.log("stdout:", stdout.trimEnd());
if (stderr) console.error("stderr:", stderr.trimEnd());
