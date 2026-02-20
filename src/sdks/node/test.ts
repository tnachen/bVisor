import { Sandbox } from "bvisor";

const cmds = [
  // "echo 'Hello, world!'",
  // "sleep 1",
  // "pwd",
  // "ls",
  // "curl -s https://www.google.com",
  // "python3 --version",
  "touch hello.py",
  "ls",
  "echo 'print(\"Hello, world!\")' > hello.py",
  "ls",
  "cat hello.py",
  // "chmod +x hello.py",
  // "python3 hello.py",
];

const sb = new Sandbox();
for (const cmd of cmds) {
  const output = sb.runCmd(cmd);
  console.log(cmd, "->", "(stdout):", await output.stdout());
  console.log(
    cmd,
    "->",
    "(stderr):",
    `\x1b[31m${await output.stderr()}\x1b[0m`,
  );
}
