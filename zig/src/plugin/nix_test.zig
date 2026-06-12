const std = @import("std");
const nix = @import("nix.zig");
const t = std.testing;

// Captured (abridged) `nix flake metadata --json` outputs.

test "parseMetadata: github ref appends percent-encoded narHash" {
	const json =
		\\{"description":"x","lastModified":1700000000,
		\\ "locked":{"lastModified":1700000000,"narHash":"sha256-AB+cd/ef=","owner":"o","repo":"r","rev":"0123abcd0123abcd0123abcd0123abcd0123abcd","type":"github"},
		\\ "original":{"owner":"o","repo":"r","type":"github"},
		\\ "url":"github:o/r/0123abcd0123abcd0123abcd0123abcd0123abcd"}
	;
	var m = try nix.parseMetadata(t.allocator, json);
	defer m.deinit(t.allocator);
	try t.expectEqualStrings("github:o/r/0123abcd0123abcd0123abcd0123abcd0123abcd?narHash=sha256-AB%2Bcd%2Fef%3D", m.locked_url);
	try t.expectEqualStrings("0123abcd0123abcd0123abcd0123abcd0123abcd", m.rev.?);
	try t.expectEqualStrings("sha256-AB+cd/ef=", m.nar_hash);
}

test "parseMetadata: path flake already carries narHash, no rev" {
	const json =
		\\{"locked":{"lastModified":1700000001,"narHash":"sha256-zzz=","path":"/home/u/plug","type":"path"},
		\\ "original":{"path":"/home/u/plug","type":"path"},
		\\ "url":"path:/home/u/plug?lastModified=1700000001&narHash=sha256-zzz%3D"}
	;
	var m = try nix.parseMetadata(t.allocator, json);
	defer m.deinit(t.allocator);
	try t.expectEqualStrings("path:/home/u/plug?lastModified=1700000001&narHash=sha256-zzz%3D", m.locked_url);
	try t.expect(m.rev == null);
	try t.expectEqualStrings("sha256-zzz=", m.nar_hash);
}

test "parseMetadata: git+https with ?dir gets & separator" {
	const json =
		\\{"locked":{"narHash":"sha256-q=","rev":"deadbeefdeadbeefdeadbeefdeadbeefdeadbeef","type":"git","url":"https://e.com/g/r"},
		\\ "url":"git+https://e.com/g/r?dir=flake&rev=deadbeefdeadbeefdeadbeefdeadbeefdeadbeef"}
	;
	var m = try nix.parseMetadata(t.allocator, json);
	defer m.deinit(t.allocator);
	try t.expect(std.mem.startsWith(u8, m.locked_url, "git+https://e.com/g/r?dir=flake&rev="));
	try t.expect(std.mem.endsWith(u8, m.locked_url, "&narHash=sha256-q%3D"));
}

test "parseMetadata: malformed input" {
	try t.expectError(error.BadMetadata, nix.parseMetadata(t.allocator, "not json"));
	try t.expectError(error.BadMetadata, nix.parseMetadata(t.allocator, "{\"url\":\"x\"}"));
	try t.expectError(error.BadMetadata, nix.parseMetadata(t.allocator, "{\"url\":\"x\",\"locked\":{}}"));
}

test "stderr helpers" {
	try t.expect(nix.stderrSaysMissingAttribute("error: flake 'path:/x' does not provide attribute 'cogboxPlugin.networkRules'"));
	try t.expect(nix.stderrSaysMissingAttribute("error: attribute 'networkRules' ... has no attribute"));
	try t.expect(!nix.stderrSaysMissingAttribute("error: infinite recursion encountered"));
	try t.expectEqualStrings("short", nix.stderrTail("  short \n"));
}
