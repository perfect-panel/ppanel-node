package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

var (
	version  = "TempVersion" //use ldflags replace
	codename = "PPanel-node"
	intro    = "A PPanel backend based on multi core"
)

var versionCommand = cobra.Command{
	Use:   "version",
	Short: "Print version info",
	Run: func(_ *cobra.Command, _ []string) {
		showVersion()
	},
}

func init() {
	command.AddCommand(&versionCommand)
}

func showVersion() {
	fmt.Println(`
	______ ______                    _ 
	| ___ \| ___ \                  | |
	| |_/ /| |_/ /__ _  _ __    ___ | |
	|  __/ |  __// _  ||  _ \  / _ \| |
	| |    | |  | (_| || | | ||  __/| |
	\_|    \_|   \__,_||_| |_| \___||_|
	`)
	fmt.Printf("%s %s (%s) \n", codename, version, intro)
}
