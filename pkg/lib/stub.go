//go:build !compute

package lib

import (
	"github.com/praetorian-inc/capability-sdk/pkg/capability"
	"github.com/praetorian-inc/capability-sdk/pkg/capmodel"
)

func (d *Discovery) Invoke(_ capability.ExecutionContext, _ capmodel.Preseed, _ capability.Emitter) error {
	return nil
}
