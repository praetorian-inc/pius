//go:build !compute

package lib

import (
	"github.com/praetorian-inc/capability-sdk/pkg/capability"
	"github.com/praetorian-inc/capability-sdk/pkg/capmodel"
)

func (d *DomainDiscovery) Invoke(_ capability.ExecutionContext, _ capmodel.Domain, _ capability.Emitter) error {
	return nil
}
