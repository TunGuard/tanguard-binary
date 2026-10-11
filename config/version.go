package config

// This is the canonical version set at release time.
// The dashboard reads this to detect updates and to display the current
// build version. It is also exposed via the API.
//
// During development builds (not git-tagged), the version may be overridden
// by the linker (ldflags -X). We avoid embedding a timestamp to ensure
// reproducible builds. For tagged releases, the tag should match this value
// (e.g. v2.4.0).
var Version = "2.4.17"
