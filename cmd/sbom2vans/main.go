package main

import (
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/google/osv-scanner/pkg/osvscanner"
	"github.com/spf13/cobra"
)

func main() {

	var SBOMInputPaths string
	var CVEs []CVE

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

				for _, alias := range vf.Vulnerability.Aliases {
					if strings.HasPrefix(alias, "CVE") {

						// Check if CVE already exists, if not, add it
						if !isCVEExist(CVEs, alias) {

							CVEs = append(CVEs, CVE{
								Name:      vf.Package.Name,
								Version:   vf.Package.Version,
								Ecosystem: vf.Package.Ecosystem,
								CVE:       alias,
							})
						}

					}
				}
			}

			// print all CVEs
			for _, cve := range CVEs {
				fmt.Printf("CVE: %s, eco: %s, name: %s, ver: %s!\n", cve.CVE, cve.Ecosystem, cve.Name, cve.Version)
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

type CVE struct {
	Name      string `json:"name"`
	Version   string `json:"version"`
	Ecosystem string `json:"ecosystem"`
	CVE       string `json:"cve"`
}

func isCVEExist(cves []CVE, cve string) bool {

	for _, v := range cves {
		if v.CVE == cve {
			return true
		}
	}

	return false
}
