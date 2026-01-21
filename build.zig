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

    // Build and install zig tests for running on host
    const host_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/main.zig"),
            .target = host_target,
            .optimize = optimize,
        }),
    });
    b.installArtifact(host_tests);

    // Build and install zig tests for linux running in docker
    const linux_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/main.zig"),
            .target = linux_target,
            .optimize = optimize,
        }),
    });
    b.installArtifact(linux_tests);

    // Add CLI commands for build.zig

    // 'run' mounts built linux exe into a linux container and runs it there
    const cli_step = b.step("run", "Run executable in a Linux container");
    const runner_args = [_][]const u8{ "docker", "run", "--rm", "-v", "./zig-out:/zig-out", "alpine", "/zig-out/bin/bVisor" };
    const runner = b.addSystemCommand(&runner_args);
    var runner_step = runner.step;
    runner_step.dependOn(b.getInstallStep()); // docker run command depends on linux exe having been built
    cli_step.dependOn(&runner_step); // ensure run command

    // Build unit tests for host target
    const host_test_step = b.step("test", "Run unit tests on host");
    const host_unit_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/main.zig"),
            .target = host_target,
            .optimize = optimize,
        }),
    });
    const host_test_run = b.addRunArtifact(host_unit_tests);
    host_test_step.dependOn(&host_test_run.step);
}
