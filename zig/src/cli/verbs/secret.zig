// `cogbox secret` - bind/list/remove operator-held credentials in the global
// host-side secret store (<config>/secrets/). Plugins REQUEST a secret by name
// + audience (cogboxPlugin.<attr>.inject); the operator binds the value here so
// it stays host-side and out of the guest. Mirrors verbs/l7.zig's shape but
// resolves the GLOBAL store (no --name), since operator secrets are shared
// across an account's instances.

const std = @import("std");
const help = @import("../help.zig");
const paths = @import("../paths.zig");
const secret_module = @import("secret_module");

pub fn run(
	allocator: std.mem.Allocator,
	io: std.Io,
	p: *const paths.Paths,
	argv: []const []const u8,
) !void {
	if (argv.len > 0 and (std.mem.eql(u8, argv[0], "--help") or std.mem.eql(u8, argv[0], "-h"))) {
		try help.print(io, help.SECRET);
		return;
	}

	const secrets_dir = try paths.globalSecretsDir(allocator, p);
	defer allocator.free(secrets_dir);

	try secret_module.dispatch(allocator, io, secrets_dir, argv);
}
