package main

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"regexp"
	"strings"

	"github.com/google/osv-scanner/pkg/lockfile"
	"github.com/google/osv-scanner/pkg/models"
	"github.com/google/osv-scanner/pkg/osvscanner"
	"github.com/google/osv-scanner/pkg/reporter"
	"github.com/nics-tw/sbom2vans/internal/sbom"
	"github.com/package-url/packageurl-go"
	"github.com/pandatix/nvdapi/v2"
	"github.com/spf13/cobra"
)

func main() {

	var SBOMInputPaths string
	var VANSKey string
	var OId string
	var UnitName string
	var vansData VANS
	var VANSEndpoint string
	NVDAPIKey := os.Getenv("NVD_API_KEY")

	if os.Getenv("VANS_API_ENDPOINT") == "" {
		VANSEndpoint = "https://vans.testing.nat.gov.tw"
	} else {
		VANSEndpoint = os.Getenv("VANS_API_ENDPOINT")
	}

	var rootCmd = &cobra.Command{
		Use:   "sbom2vans",
		Short: "SBOM 轉換為 VANS 機關資產管理 CLI 工具",
		Run: func(cmd *cobra.Command, args []string) {

			vansData.APIKey = VANSKey

			CVEs := getCPEFromSBOM(SBOMInputPaths, NVDAPIKey)
			r := &reporter.VoidReporter{}
			pkgs, err := scanSBOMFile(r, SBOMInputPaths, false)
			if err != nil {
				log.Fatal(err)
			}

			// save all packages to VANS data
			// TODO: it might have some duplicate packages in CVE lists
			for _, pkg := range pkgs {

				parsedPURL, err := packageurl.FromString(pkg.PURL)
				if err != nil {
					log.Fatal(err)
				}

				vansData.Data = append(vansData.Data, VANSItem{
					OID:            OId,
					UnitName:       UnitName,
					AssetNumber:    "1",
					ProductName:    pkg.PURL,
					ProductVendor:  parsedPURL.Type,
					ProductVersion: parsedPURL.Version,
					Category:       "software",
					CPE23:          "N/A",
					ProductCPEName: pkg.PURL,
				})

			}

			for _, cve := range CVEs {

				if cve.CPE != "" && cve.ProductCPEName != "" {
					parts := strings.Split(cve.CPE, ":")
					vansData.Data = append(vansData.Data, VANSItem{
						OID:            OId,
						UnitName:       UnitName,
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

			fmt.Println("OSV-Scanner 查詢有 CVE 紀錄套件：")
			cvesJsonData, err := json.Marshal(CVEs)
			fmt.Println(string(cvesJsonData))

			// Marshal your struct into JSON
			jsonData, err := json.Marshal(vansData)
			// fmt.Println(string(jsonData))

			if err != nil {
				fmt.Println("Error marshalling JSON:", err)
				return
			}

			fmt.Println("上傳至 VANS 中...")
			// Skip SSL verification as testing env
			if os.Getenv("VANS_API_ENDPOINT") == "" {
				http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
			}
			// Make a POST request
			VANSAPIEndpoint := VANSEndpoint + "/rest/vans/InsertSystemUnitproduct"
			resp, err := http.Post(VANSAPIEndpoint, "application/json", bytes.NewBuffer(jsonData))
			if err != nil {
				fmt.Println("Error making POST request:", err)
				return
			}
			defer resp.Body.Close()

			// Read response body
			body, err := io.ReadAll(resp.Body)
			if err != nil {
				fmt.Println("Error reading response body:", err)
				return
			}

			// Print response body
			fmt.Println(string(body))

		},
	}

	rootCmd.Flags().StringVarP(&SBOMInputPaths, "input-file", "i", "", "指定 SBOM 檔案目錄位置")
	rootCmd.Flags().StringVarP(&VANSKey, "vans-key", "k", "", "指定 VANS 機關資產管理 API key")
	rootCmd.Flags().StringVarP(&OId, "oid", "", "", "機關 Object Identifier (OID)，可以至 OID 網站 https://oid.nat.gov.tw/OIDWeb/ 查詢")
	rootCmd.Flags().StringVarP(&UnitName, "unit-name", "u", "", "機關名稱，如：監察院")

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

// get cpe from sbom
func getCPEFromSBOM(SBOMInputPaths string, apiKey string) []CVE {
	var CVEs []CVE

	flagged := []string{
		SBOMInputPaths,
	} // your real code

	fmt.Println("開始掃描 SBOM 檔案...")
	vulnResult, _ := osvscanner.DoScan(osvscanner.ScannerActions{
		SBOMPaths: flagged,
	}, nil)

	// Get all CVEs from the SBOM by using osv-scanner
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
	return CVEs
}

func scanSBOMFile(r reporter.Reporter, path string, fromFSScan bool) ([]scannedPackage, error) {
	var errs []error
	var packages []scannedPackage
	for _, provider := range sbom.Providers {
		if fromFSScan && !provider.MatchesRecognizedFileNames(path) {
			// Skip if filename is not usually a sbom file of this format.
			// Only do this if this is being done in a filesystem scanning context, where we need to be
			// careful about spending too much time attempting to parse unrelated files.
			// If this is coming from an explicit scan argument, be more relaxed here since it's common for
			// filenames to not conform to expected filename standards.
			continue
		}

		// Opening file inside loop is OK, since providers is not very long,
		// and it is unlikely that multiple providers accept the same file name
		file, err := os.Open(path)
		if err != nil {
			return nil, err
		}
		defer file.Close()

		ignoredCount := 0
		err = provider.GetPackages(file, func(id sbom.Identifier) error {
			_, err := models.PURLToPackage(id.PURL)
			if err != nil {
				ignoredCount++
				//nolint:nilerr
				return nil
			}
			packages = append(packages, scannedPackage{
				PURL: id.PURL,
			})

			return nil
		})
		if err == nil {
			// Found a parsable format.
			if len(packages) == 0 {
				// But no entries found, so maybe not the correct format
				errs = append(errs, sbom.InvalidFormatError{
					Msg: "no Package URLs found",
					Errs: []error{
						fmt.Errorf("scanned %s as %s SBOM, but failed to find any package URLs, this is required to scan SBOMs", path, provider.Name()),
					},
				})

				continue
			}
			r.Infof(
				"Scanned %s as %s SBOM and found %d %s\n",
				path,
				provider.Name(),
				len(packages),
				// output.Form(len(packages), "package", "packages"),
			)
			if ignoredCount > 0 {
				r.Infof(
					"Ignored %d %s with invalid PURLs\n",
					ignoredCount,
					// output.Form(ignoredCount, "package", "packages"),
				)
			}

			return packages, nil
		}

		var formatErr sbom.InvalidFormatError
		if errors.As(err, &formatErr) {
			errs = append(errs, err)
			continue
		}

		return nil, err
	}

	// Don't log these errors if we're coming from an FS scan, since it can get very noisy.
	if !fromFSScan {
		r.Infof("Failed to parse SBOM using all supported formats:\n")
		for _, err := range errs {
			r.Infof(err.Error() + "\n")
		}
	}

	return packages, nil
}

type scannedPackage struct {
	PURL      string
	Name      string
	Ecosystem lockfile.Ecosystem
	Commit    string
	Version   string
	DepGroups []string
}
