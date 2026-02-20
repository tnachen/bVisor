import { Sandbox } from "bvisor";

const cmds = [
  "echo 'Hello, world!'",
  "sleep 1",
  "pwd",
  "curl -s https://www.google.com",
  "python3 --version",
  "touch hello.py",
  "ls",
  "echo 'print(\"Hello, world!\")' > hello.py",
  "chmod +x hello.py",
  "python3 hello.py",
];

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
