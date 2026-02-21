import { Sandbox } from "bvisor";

const isInteractive = Bun.argv.includes("--interactive");
const logLevel = Bun.argv.includes("--log-level")
  ? Bun.argv[Bun.argv.indexOf("--log-level") + 1]
  : "OFF";

const sb = new Sandbox();
sb.setLogLevel(logLevel);

if (isInteractive) {
  process.stdout.write("bvisor> ");
  for await (const line of console) {
    const cmd = line.trim();
    if (!cmd) {
      process.stdout.write("use 'exit' to exit\n");
      process.stdout.write("bvisor> ");
      continue;
    }
    if (cmd === "exit") break;
    const output = sb.runCmd(cmd);
    const stdout = await output.stdout();
    const stderr = await output.stderr();
    if (stdout) process.stdout.write(stdout);
    if (stderr) process.stderr.write(`\x1b[31m${stderr}\x1b[0m`);
    process.stdout.write("bvisor> ");
  }
} else {
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

  for (const cmd of cmds) {
    const output = sb.runCmd(cmd);
    console.log("cmd:", cmd);
    console.log(
      "\n(stdout):",
      await output.stdout(),
      `\n\x1b[31m(stderr): ${await output.stderr()}\x1b[0m`,
    );
  }
}
