package main

import (
	"fmt"
	"log"
	"os"

	"github.com/google/osv-scanner/pkg/osvscanner"
	"github.com/spf13/cobra"
)

func main() {
	var name string
	var SBOMInputPaths string

	var rootCmd = &cobra.Command{
		Use:   "sbom2vans",
		Short: "A simple CLI tool",
		Run: func(cmd *cobra.Command, args []string) {

			flagged := []string{
				SBOMInputPaths,
			} // your real code

			vulnResult, err := osvscanner.DoScan(osvscanner.ScannerActions{
				SBOMPaths: flagged,
			}, nil)

			for _, vf := range vulnResult.Flatten() {
				fmt.Printf("eco: %s, name: %s, ver: %s!\n", vf.Package.Ecosystem, vf.Package.Name, vf.Package.Version)
				fmt.Printf("vul.Aliases: %s\n", vf.Vulnerability.Aliases)
			}

			if err != nil {
				log.Fatal(err)
			}

		},
	}

	rootCmd.Flags().StringVarP(&name, "name", "n", "World", "Specify a name")
	rootCmd.Flags().StringVarP(&SBOMInputPaths, "input-file", "i", "", "Specify a SBOM file to scan")

	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
