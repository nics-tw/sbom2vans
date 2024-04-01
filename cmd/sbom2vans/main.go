package main

import (
	"fmt"
	"log"
	"os"

	"github.com/google/osv-scanner/pkg/osvscanner"
	"github.com/spf13/cobra"
)

func main() {

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

			// vulnResult.Flatten 輸出可能會有重複，原因是 vf.Package, vf.Package.Vulnerability 會被壓成同一個 struct
			for _, vf := range vulnResult.Flatten() {
				fmt.Printf("eco: %s, name: %s, ver: %s!\n", vf.Package.Ecosystem, vf.Package.Name, vf.Package.Version)
				fmt.Printf("vul.Aliases: %s\n", vf.Vulnerability.Aliases)
			}

			if err != nil {
				log.Fatal(err)
			}

		},
	}

	rootCmd.Flags().StringVarP(&SBOMInputPaths, "input-file", "i", "", "Specify a SBOM file to scan")

	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
