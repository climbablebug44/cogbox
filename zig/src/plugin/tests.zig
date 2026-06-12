// Aggregator file pulling unit tests from every module.
// Run via `zig build test`.

const std = @import("std");

test {
	std.testing.refAllDecls(@import("cli.zig"));
	std.testing.refAllDecls(@import("name.zig"));
	std.testing.refAllDecls(@import("compose.zig"));
	std.testing.refAllDecls(@import("mutate.zig"));
	std.testing.refAllDecls(@import("nix.zig"));
	_ = @import("name_test.zig");
	_ = @import("compose_test.zig");
	_ = @import("mutate_test.zig");
	_ = @import("nix_test.zig");
}
