package main

import (
	"fmt"
	"log"
	"os"
	"regexp"
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

						if !isCVEExist(CVEs, alias) {

							if isPackageExist(CVEs, vf.Package.Name) {
								// Find the package and add the CVE to the CVE array
								for i, cve := range CVEs {
									if cve.Name == vf.Package.Name {
										CVEs[i].CVE = append(CVEs[i].CVE, alias)
									}
								}
							} else {

								CVEs = append(CVEs, CVE{
									Name:      vf.Package.Name,
									Version:   extractVersion(vf.Package.Version),
									Ecosystem: vf.Package.Ecosystem,
									CVE:       []string{alias},
								})
							}
						}
					}
				}
			}

			// print all CVEs
			for _, cve := range CVEs {
				fmt.Printf("CVE: %v, eco: %s, name: %s, ver: %s\n", cve.CVE, cve.Ecosystem, cve.Name, cve.Version)
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
	Name      string   `json:"name"`
	Version   string   `json:"version"`
	Ecosystem string   `json:"ecosystem"`
	CVE       []string `json:"cve"`
}

func isCVEExist(cves []CVE, cve string) bool {

	for _, v := range cves {
		for _, c := range v.CVE {
			if c == cve {
				return true
			}
		}
	}

	return false
}

func isPackageExist(cves []CVE, name string) bool {

	for _, v := range cves {
		if v.Name == name {
			return true
		}
	}

	return false
}

func ptr[T any](t T) *T {
	return &t
}

func extractVersion(input string) string {
	re := regexp.MustCompile(`[vV]?(\d+\.\d+(\.\d+)?)`)
	match := re.FindStringSubmatch(input)
	if len(match) > 1 {
		return match[1]
	}
	return ""
}
