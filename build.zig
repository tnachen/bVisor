const std = @import("std");

pub fn build(b: *std.Build) void {
    const optimize = b.standardOptimizeOption(.{});

    // Target multiple platforms based on testing flags
    const linux_target = b.resolveTargetQuery(.{
        .cpu_arch = .aarch64, // ARM64 for Apple Silicon Macs running Docker, update for other targets
        .os_tag = .linux,
        .abi = .musl,
    });
    const host_target = b.graph.host;

    // Build and install linux executable
    // to ./zig-out/bin
    const linux_exe = b.addExecutable(.{
        .name = "bVisor",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/main.zig"),
            .target = linux_target,
            .optimize = optimize,
        }),
    });
    b.installArtifact(linux_exe);

    // Build zig tests for running on host
    const host_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/main.zig"),
            .target = host_target,
            .optimize = optimize,
        }),
    });

    // Build and install zig tests for running in linux container
    const linux_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/main.zig"),
            .target = linux_target,
            .optimize = optimize,
        }),
    });
    const test_install = b.addInstallArtifact(linux_tests, .{ .dest_sub_path = "tests" });
    b.getInstallStep().dependOn(&test_install.step);

    // 'run' mounts built linux exe into a linux container and runs it there
    const run_cli_step = b.step("run", "Run executable in a Linux container");
    const run_args = [_][]const u8{ "docker", "run", "--rm", "-v", "./zig-out:/zig-out", "alpine", "/zig-out/bin/bVisor" };
    const run_cmd = b.addSystemCommand(&run_args);
    run_cmd.step.dependOn(b.getInstallStep()); // docker run depends on linux exe being built
    run_cli_step.dependOn(&run_cmd.step);

    // 'test' runs unit tests on host
    const test_cli_step = b.step("test", "Run unit tests on host");
    const test_cmd = b.addRunArtifact(host_tests);
    test_cli_step.dependOn(&test_cmd.step);

    // 'test-linux' runs unit tests in linux container
    const test_linux_cli_step = b.step("test-linux", "Run unit tests in linux container");
    const test_linux_args = [_][]const u8{ "docker", "run", "--rm", "-v", "./zig-out:/zig-out", "alpine", "/zig-out/bin/bVisor-test" };
    const test_linux_cmd = b.addSystemCommand(&test_linux_args);
    test_linux_cmd.step.dependOn(b.getInstallStep()); // docker run depends on linux tests being built
    test_linux_cli_step.dependOn(&test_linux_cmd.step);
}
