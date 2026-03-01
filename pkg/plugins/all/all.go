// Package all imports all Pius plugins to trigger their init() registration.
// Import this package to load all available plugins into the registry.
package all

import (
	// CIDR plugins
	_ "github.com/praetorian-inc/pius/pkg/plugins/cidrs"
	// Domain plugins
	_ "github.com/praetorian-inc/pius/pkg/plugins/domains"
)
