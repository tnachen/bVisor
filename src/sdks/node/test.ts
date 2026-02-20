import { Sandbox } from "bvisor";

const isInteractive = process.argv.includes("--interactive");

const sb = new Sandbox();

if (isInteractive) {
  const reader = require("readline").createInterface({
    input: process.stdin,
    output: process.stdout,
  });

  const prompt = () => {
    reader.question("bvisor> ", async (line: string) => {
      const cmd = line.trim();
      if (!cmd) {
        reader.close();
        return;
      }
      const output = sb.runCmd(cmd);
      const stdout = await output.stdout();
      const stderr = await output.stderr();
      if (stdout) process.stdout.write(stdout);
      if (stderr) process.stderr.write(`\x1b[31m${stderr}\x1b[0m`);
      prompt();
    });
  };
  prompt();
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
