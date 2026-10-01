// Tiny Darwin/ARM64 data-export module — the e2e's cross-module bind
// target. The arm64e fixture imports host_value as DATA (a non-auth chained
// bind entry); loading this module first puts the export into the
// DynamicLinker's global scope, so the bind resolves through the exact
// SymbolResolver path guest-to-guest binding always uses.
//
// Build (committed prebuilt is hostdata_darwin_arm64.dylib; rebuild on
// macOS with build_darwin_arm64e_fixture.sh):
//   clang -arch arm64 -target arm64-apple-macos11 -dynamiclib \
//         -fno-builtin -fno-stack-protector -O2 \
//         -Wl,-no_fixup_chains \
//         -o hostdata_darwin_arm64.dylib hostdata_darwin_arm64.c

long host_value = 12345678;
