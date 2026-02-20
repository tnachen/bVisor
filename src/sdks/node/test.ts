import { Sandbox } from "bvisor";

const cmds = [
  "echo 'Hello, world!'",
  // "sleep 1",
  "pwd",
  "ls",
  "curl -s https://www.google.com",
  "python --version",
];

for (const cmd of cmds) {
  const sb = new Sandbox();
  const output = sb.runCmd(cmd);
  console.log(cmd, "->", "(stdout):", await output.stdout());
  console.log(
    cmd,
    "->",
    "(stderr):",
    `\x1b[31m${await output.stderr()}\x1b[0m`,
  );
}
