package runner

import (
	"github.com/spf13/cobra"

	_ "github.com/praetorian-inc/pius/pkg/plugins/all"
)

// ANSI escape codes
const (
	red   = "\x1b[31m"
	bold  = "\x1b[1m"
	reset = "\x1b[0m"
)

var banner = `
        ........::..::::::::::.      ...       ..     .....    ..
.:::......:.:..:.:.... .::::::.       ..:.... ....:::::::::::::::::::.....
:::::::::::::::....:..  ...   ..    .::.:::::::::::::::::::::::::::::::...
      ..::::::::::::::.` + red + `____  (_)_  _______` + reset + `::::::::::::::::::  ..
        .::::::::::::. ` + red + `/ __ \/ / / / / ___/` + reset + ` :...:.::::::::::...
         .:::::::::   ` + red + `/ /_/ / / /_/ (__  )` + reset + `  ..:::....:::::::::.....
          ..::.. ..  ` + red + `/ .___/_/\__,_/____/` + reset + ` .:::::::::::::::::::::.
            ...:..  ` + red + `/_/` + reset + `          ::::::::::::::.:::..:::.:::::::
               ...:::..       ` + red + bold + `Map Your Assets` + reset + `    ..   ...  ..
                 :::::::..  ` + bold + `Praetorian Security, Inc.` + reset + `    ...::.....
                 ::::::::::          :::::..              .... ....
                  .:::::::          .:::::..:               .:::::      .
                   ::::..            .:::.                .::::::::.
                  .:::..              ..                  ...  .::.    .
                  .:.                                            .    ..
                  ..
`

var rootCmd = &cobra.Command{
	Use:   "pius",
	Short: "Organizational asset discovery tool",
	Long:  banner + "\nPius discovers CIDR blocks and domains associated with an organization using multiple OSINT data sources.",
}

// SetVersion sets the version string displayed by --version.
func SetVersion(v string) {
	rootCmd.Version = v
}

// Execute runs the root command.
func Execute() error {
	return rootCmd.Execute()
}

func init() {
	rootCmd.AddCommand(newRunCmd())
	rootCmd.AddCommand(newListCmd())
}
