package runner

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/praetorian-inc/pius/pkg/plugins"
)

func newListCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List available plugins",
		Run: func(cmd *cobra.Command, args []string) {
			all := plugins.All()
			if len(all) == 0 {
				fmt.Println("No plugins registered.")
				return
			}

			fmt.Printf("%-20s %-10s %-10s %s\n", "NAME", "CATEGORY", "PHASE", "DESCRIPTION")
			fmt.Printf("%-20s %-10s %-10s %s\n", "----", "--------", "-----", "-----------")

			for _, name := range plugins.List() {
				p, ok := plugins.Get(name)
				if !ok {
					continue
				}
				phaseStr := phaseLabel(p.Phase())
				fmt.Printf("%-20s %-10s %-10s %s\n",
					p.Name(), p.Category(), phaseStr, p.Description())
			}
		},
	}
}

func phaseLabel(phase int) string {
	switch phase {
	case 1:
		return "phase-1"
	case 2:
		return "phase-2"
	default:
		return "independent"
	}
}
