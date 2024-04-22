package main

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"regexp"
	"strings"

	"github.com/google/osv-scanner/pkg/osvscanner"
	"github.com/pandatix/nvdapi/v2"
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
									Version:   vf.Package.Version,
									Ecosystem: vf.Package.Ecosystem,
									CVE:       []string{alias},
								})
							}
						}
					}
				}
			}

			// Get CPEs for each CVE
			for i, cve := range CVEs {
				apiKey := ""
				client, err := nvdapi.NewNVDClient(&http.Client{}, apiKey)
				if err != nil {
					log.Fatal(err)
				}
				resp, err := nvdapi.GetCVEs(client, nvdapi.GetCVEsParams{
					CVEID: ptr(cve.CVE[0]),
				})

				if err != nil {
					log.Fatal(err)
				}

				// Only request per CVE for each request, therefore, the first element is the only one

				if resp.Vulnerabilities[0].CVE.Configurations != nil && len(resp.Vulnerabilities[0].CVE.Configurations[0].Nodes) > 0 {
					for _, config := range resp.Vulnerabilities[0].CVE.Configurations {
						for _, node := range config.Nodes {
							// print all cpe_match
							for _, cpe := range node.CPEMatch {
								if strings.Contains(cpe.Criteria, extractPackageName(cve.Name)) {

									// Split the CPE and replace the version
									splitCPE := strings.Split(cpe.Criteria, ":")
									splitCPE[5] = extractVersion(cve.Version)
									cpeWithVersion := strings.Join(splitCPE, ":")
									CVEs[i].CPE = cpeWithVersion

									resp, err := nvdapi.GetCPEs(client, nvdapi.GetCPEsParams{
										CPEMatchString: ptr(cpeWithVersion),
									})

									if err != nil {
										log.Fatal(err)
									}

									// Get CPE titles as VANS request product_cpename column
									if len(resp.Products) > 0 {
										for _, title := range resp.Products[0].CPE.Titles {
											if title.Lang == "en" {
												CVEs[i].ProductCPEName = title.Title
											}
										}
									}
								}
							}
						}
					}
				}

			}
			var vansData VANS
			vansData.APIKey = ""
			for _, cve := range CVEs {
				// purl := packageurl.NewPackageURL(cve.Ecosystem, "", cve.Name, cve.Version, nil, "")
				// fmt.Printf("CVE: %v, eco: %s, name: %s, ver: %s, cpe: %s, cpeName: %s\n", cve.CVE, cve.Ecosystem, cve.Name, cve.Version, cve.CPE, cve.ProductCPEName)

				if cve.CPE != "" && cve.ProductCPEName != "" {
					parts := strings.Split(cve.CPE, ":")
					vansData.Data = append(vansData.Data, VANSItem{
						OID:            "2.16.886.101.20007",
						UnitName:       "監察院",
						AssetNumber:    "1",
						ProductName:    parts[4],
						ProductVendor:  parts[3],
						ProductVersion: parts[5],
						Category:       "software",
						CPE23:          cve.CPE,
						ProductCPEName: cve.ProductCPEName,
					})
				}

			}

			// Marshal your struct into JSON
			jsonData, err := json.Marshal(vansData)
			fmt.Println(string(jsonData))

			if err != nil {
				fmt.Println("Error marshalling JSON:", err)
				return
			}

			// Skip SSL verification as testing env
			http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
			// Make a POST request
			resp, err := http.Post("https://vans.nat.gov.tw/rest/vans/InsertSystemUnitproduct", "application/json", bytes.NewBuffer(jsonData))
			if err != nil {
				fmt.Println("Error making POST request:", err)
				return
			}
			defer resp.Body.Close()

			// Read response body
			body, err := ioutil.ReadAll(resp.Body)
			if err != nil {
				fmt.Println("Error reading response body:", err)
				return
			}

			// Print response status and body
			fmt.Println("Response Status:", resp.Status)
			fmt.Println("Response Body:", string(body))

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
	Name           string   `json:"name"`
	Version        string   `json:"version"`
	Ecosystem      string   `json:"ecosystem"`
	CVE            []string `json:"cve"`
	CPE            string   `json:"cpe"`
	ProductCPEName string   `json:"product_cpename"`
}

type VANS struct {
	APIKey string     `json:"api_key"`
	Data   []VANSItem `json:"data"`
}

type VANSItem struct {
	OID            string `json:"oid"`
	UnitName       string `json:"unit_name"`
	AssetNumber    string `json:"asset_number"`
	ProductName    string `json:"product_name"`
	ProductVendor  string `json:"product_vendor"`
	ProductVersion string `json:"product_version"`
	Category       string `json:"category"`
	CPE23          string `json:"cpe23"`
	ProductCPEName string `json:"product_cpename"`
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

func extractPackageName(input string) string {
	parts := strings.Split(input, "/")
	if len(parts) == 0 {
		return ""
	}
	lastPart := parts[len(parts)-1]
	// Remove any version suffix if present
	if strings.HasPrefix(lastPart, "v") && strings.Count(lastPart, ".") >= 2 {
		lastPart = strings.Join(parts[len(parts)-2:], "/")
	}
	return lastPart
}
