package version

// Version is the release stamp. goreleaser overrides it at link time
// (-X crashscope/internal/version.Version=...), so a release binary always
// reports its tag even if this default lags behind.
var Version = "0.1.0"
