package config

// Version is overridable at build time with
//
//	-ldflags "-X tanguard/config.Version=$(git describe --tags --always)"
//
// so a tagged release reports its own version. Hardcoding it meant every
// release claimed to be the same build, and the dashboard offered an update
// that could never be installed.
var Version = "2.4.2-dev"
