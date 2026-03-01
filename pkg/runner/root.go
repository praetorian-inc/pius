package runner

import (
	"github.com/spf13/cobra"

	_ "github.com/praetorian-inc/pius/pkg/plugins/all"
)

var rootCmd = &cobra.Command{
	Use:   "pius",
	Short: "Organizational asset discovery tool",
	Long:  "Pius discovers CIDR blocks and domains associated with an organization using multiple OSINT data sources.",
}

// Execute runs the root command.
func Execute() error {
	return rootCmd.Execute()
}

func init() {
	rootCmd.AddCommand(newRunCmd())
	rootCmd.AddCommand(newListCmd())
}
