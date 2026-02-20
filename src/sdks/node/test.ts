import { Sandbox } from "bvisor";

const cmds = ["curl -s https://www.google.com"];

const sb = new Sandbox();
for (const cmd of cmds) {
  const output = sb.runCmd(cmd);
  console.log("cmd:", cmd);
  console.log(
    "\n(stdout):",
    await output.stdout(),
    `\n\x1b[31m(stderr): ${await output.stderr()}\x1b[0m`,
  );
}
