const std = @import("std");
const builtin = @import("builtin");

pub fn build(b: *std.Build) void {
    const optimize = b.standardOptimizeOption(.{});

    const Arch = enum { aarch64, x86_64 };
    const arch = b.option(Arch, "arch", "Architecture for Docker run/test (default: host)") orelse switch (builtin.cpu.arch) {
        .aarch64 => .aarch64,
        .x86_64 => .x86_64,
        else => @compileError("unsupported host architecture"),
    };
    const cpu_arch: std.Target.Cpu.Arch = switch (arch) {
        .aarch64 => .aarch64,
        .x86_64 => .x86_64,
    };
    const bin_suffix: []const u8 = switch (arch) {
        .aarch64 => "-aarch64",
        .x86_64 => "-x86_64",
    };

    const targets = [_]struct {
        cpu_arch: std.Target.Cpu.Arch,
        suffix: []const u8,
    }{
        .{ .cpu_arch = .aarch64, .suffix = "-aarch64" },
        .{ .cpu_arch = .x86_64, .suffix = "-x86_64" },
    };

    // Build node bindings library for each platform
    const node_api = b.dependency("node_api", .{});

    const node_platforms = [_]struct {
        cpu_arch: std.Target.Cpu.Arch,
        abi: std.Target.Abi,
        dest_dir: []const u8,
    }{
        .{ .cpu_arch = .aarch64, .abi = .musl, .dest_dir = "../src/sdks/node/platforms/linux-arm64-musl" },
        .{ .cpu_arch = .aarch64, .abi = .gnu, .dest_dir = "../src/sdks/node/platforms/linux-arm64-gnu" },

        .{ .cpu_arch = .x86_64, .abi = .musl, .dest_dir = "../src/sdks/node/platforms/linux-x64-musl" },
        .{ .cpu_arch = .x86_64, .abi = .gnu, .dest_dir = "../src/sdks/node/platforms/linux-x64-gnu" },
    };

    var node_installs: [node_platforms.len]*std.Build.Step = undefined;
    for (node_platforms, 0..) |platform, i| {
        const target = b.resolveTargetQuery(.{
            .cpu_arch = platform.cpu_arch,
            .os_tag = .linux,
            .abi = platform.abi,
        });

        const core_module = b.createModule(.{
            .root_source_file = b.path("src/core/root.zig"),
            .target = target,
            .optimize = optimize,
        });

        const node_lib = b.addLibrary(.{
            .name = "libbvisor",
            .linkage = .dynamic,
            .root_module = b.createModule(.{
                .root_source_file = b.path("src/sdks/node/zig/root.zig"),
                .target = target,
                .optimize = optimize,
                .link_libc = true,
            }),
        });
        node_lib.root_module.addImport("core", core_module);
        node_lib.root_module.addIncludePath(node_api.path("include"));
        node_lib.linker_allow_shlib_undefined = true;

        const install = b.addInstallArtifact(node_lib, .{
            .dest_dir = .{ .override = .{ .custom = platform.dest_dir } },
            .dest_sub_path = "libbvisor.node",
        });
        b.getInstallStep().dependOn(&install.step);
        node_installs[i] = &install.step;
    }

    // Build exe and test binaries for both architectures
    var exe_install_step: *std.Build.Step = undefined;
    var test_install_step: *std.Build.Step = undefined;
    for (targets) |t| {
        const linux_target = b.resolveTargetQuery(.{
            .cpu_arch = t.cpu_arch,
            .os_tag = .linux,
            .abi = .musl,
        });

        const linux_exe = b.addExecutable(.{
            .name = "bVisor",
            .root_module = b.createModule(.{
                .root_source_file = b.path("src/core/main.zig"),
                .target = linux_target,
                .optimize = optimize,
            }),
        });
        const exe_install = b.addInstallArtifact(linux_exe, .{
            .dest_sub_path = b.fmt("bVisor{s}", .{t.suffix}),
        });
        b.getInstallStep().dependOn(&exe_install.step);
        if (t.cpu_arch == cpu_arch) exe_install_step = &exe_install.step;

        const linux_tests = b.addTest(.{
            .root_module = b.createModule(.{
                .root_source_file = b.path("src/core/main.zig"),
                .target = linux_target,
                .optimize = optimize,
            }),
        });
        const test_install = b.addInstallArtifact(linux_tests, .{
            .dest_sub_path = b.fmt("tests{s}", .{t.suffix}),
        });
        b.getInstallStep().dependOn(&test_install.step);
        if (t.cpu_arch == cpu_arch) test_install_step = &test_install.step;
    }

    // 'run' executes the sandbox in a Linux container
    const run_cli_step = b.step("run", "Run executable in a Linux container");
    const run_cmd = b.addSystemCommand(&.{ "docker", "run", "--rm" });
    if (arch == .x86_64) run_cmd.addArgs(&.{ "--platform", "linux/amd64" });
    run_cmd.addArgs(&.{ "-v", "./zig-out:/zig-out", "alpine" });
    run_cmd.addArg(b.fmt("/zig-out/bin/bVisor{s}", .{bin_suffix}));
    run_cmd.step.dependOn(exe_install_step);
    run_cli_step.dependOn(&run_cmd.step);

    // 'test' runs unit tests in a Linux container
    const test_cli_step = b.step("test", "Run unit tests in Docker container");
    const docker_test_cmd = b.addSystemCommand(&.{ "docker", "run", "--rm" });
    if (arch == .x86_64) docker_test_cmd.addArgs(&.{ "--platform", "linux/amd64" });
    docker_test_cmd.addArgs(&.{ "-v", "./zig-out:/zig-out", "alpine" });
    docker_test_cmd.addArg(b.fmt("/zig-out/bin/tests{s}", .{bin_suffix}));
    docker_test_cmd.step.dependOn(test_install_step);
    test_cli_step.dependOn(&docker_test_cmd.step);

    // 'test-node' runs Node SDK test in a Docker container
    const node_cli_step = b.step("test-node", "Run Node SDK test.ts in Docker container against the current build");
    const node_cmd = b.addSystemCommand(&.{
        "docker", "run",                        "--rm",
        "-v",     "./src/sdks/node:/app",       "-w",
        "/app",   "oven/bun:alpine",            "sh",
        "-c",     "bun install && bun test.ts",
    });
    for (&node_installs) |step| node_cmd.step.dependOn(step);
    node_cli_step.dependOn(&node_cmd.step);
}
