import { readFileSync, writeFileSync } from "fs";
import { execSync } from "child_process";

const pkgPath = new URL("../package.json", import.meta.url).pathname;
const pkg = JSON.parse(readFileSync(pkgPath, "utf-8"));
const version = pkg.version;

const platforms = [
  "linux-arm64-musl",
  "linux-arm64-gnu",
  "linux-x64-musl",
  "linux-x64-gnu",
];

// Publish platform packages first
for (const platform of platforms) {
  console.log(`Publishing @bvisor/${platform}...`);
  execSync("bun publish --access public", {
    cwd: new URL(`../platforms/${platform}`, import.meta.url).pathname,
    stdio: "inherit",
  });
}

// Pin optionalDependencies to the current version for publishing
for (const key of Object.keys(pkg.optionalDependencies)) {
  pkg.optionalDependencies[key] = version;
}
writeFileSync(pkgPath, JSON.stringify(pkg, null, 2) + "\n");

try {
  console.log(`Publishing bvisor@${version}...`);
  execSync("bun publish --access public", {
    cwd: new URL("..", import.meta.url).pathname,
    stdio: "inherit",
  });
} finally {
  // Restore workspace:* for local dev
  for (const key of Object.keys(pkg.optionalDependencies)) {
    pkg.optionalDependencies[key] = "workspace:*";
  }
  writeFileSync(pkgPath, JSON.stringify(pkg, null, 2) + "\n");
}
