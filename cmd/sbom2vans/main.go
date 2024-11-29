package main

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
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
	var VANSEndpoint string
	var NVDKey string
	var AssetGroupCode string
	var DebugMode bool
	var VANSVersion int // 1 or 2
	var VANSData VANS
	VANSV2Data := VANSV2{Data: []VANSV2Item{}}
	var VANSAPIEndpoint string

	rootCmd := &cobra.Command{
		Use:   "sbom2vans",
		Short: "SBOM 轉換為 VANS 機關資產管理 CLI 工具",
		Run: func(cmd *cobra.Command, args []string) {
			switch VANSVersion {
			case 1:
				VANSData.APIKey = VANSKey
				VANSAPIEndpoint = VANSEndpoint + "/rest/vans/InsertSystemUnitproduct"
			case 2:
				VANSV2Data.APIKey = VANSKey
				VANSAPIEndpoint = VANSEndpoint + "/vans2/asset/InsertServerUnitproduct"
			}

			CVEs := getCPEFromSBOM(SBOMInputPaths, NVDKey)
			r := &reporter.VoidReporter{}
			pkgs, err := scanSBOMFile(r, SBOMInputPaths, false)
			if err != nil {
				log.Fatal("SBOM Error: ", err)
			}

			// save all packages to VANS data
			// TODO: it might have some duplicate packages in CVE lists
			for _, pkg := range pkgs {
				parsedPURL, err := packageurl.FromString(pkg.PURL)
				if err != nil {
					log.Fatal("packageurl Error: ", err)
				}

				if isDuplicate(VANSV2Data.Data, pkg.PURL) {
					continue
				}

				switch VANSVersion {
				case 1:
					if parsedPURL.Version != "" {
						VANSData.Data = append(VANSData.Data, VANSItem{
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
					} else {
						// cyclone format might include the project name as package without version
						VANSData.Data = append(VANSData.Data, VANSItem{
							OID:            OId,
							UnitName:       UnitName,
							AssetNumber:    "1",
							ProductName:    pkg.PURL,
							ProductVendor:  parsedPURL.Type,
							ProductVersion: "N/A",
							Category:       "software",
							CPE23:          "N/A",
							ProductCPEName: pkg.PURL,
						})
					}
				case 2:
					if parsedPURL.Version != "" {
						VANSV2Data.Data = append(VANSV2Data.Data, VANSV2Item{
							OID:            OId,
							OrgName:        UnitName,
							Identifier:     getIdentifier(),
							AssetGroupCode: AssetGroupCode,
							AssetName:      pkg.PURL,
							Brand:          parsedPURL.Type,
							Version:        parsedPURL.Version,
							CPE:            "N/A",
							CPEName:        "N/A",
						})
					} else {
						// cyclone format might include the project name as package without version
						VANSV2Data.Data = append(VANSV2Data.Data, VANSV2Item{
							OID:            OId,
							OrgName:        UnitName,
							Identifier:     getIdentifier(),
							AssetGroupCode: AssetGroupCode,
							AssetName:      pkg.PURL,
							Brand:          parsedPURL.Type,
							Version:        "N/A",
							CPE:            "N/A",
							CPEName:        "N/A",
						})
					}
				}
			}

			for _, cve := range CVEs {
				if cve.CPE != "" && cve.ProductCPEName != "" {
					parts := strings.Split(cve.CPE, ":")
					switch VANSVersion {
					case 1:
						VANSData.Data = append(VANSData.Data, VANSItem{
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
					case 2:
						VANSV2Data.Data = replaceOrAppend(VANSV2Data.Data, VANSV2Item{
							OID:            OId,
							OrgName:        UnitName,
							Identifier:     getIdentifier(),
							AssetGroupCode: AssetGroupCode,
							AssetName:      parts[4],
							Brand:          parts[3],
							Version:        parts[5],
							CPE:            cve.CPE,
							CPEName:        cve.ProductCPEName,
						})
					}
				}
			}

			fmt.Println("OSV-Scanner 查詢有 CVE 紀錄套件：")
			cvesJsonData, err := json.Marshal(CVEs)
			fmt.Println(string(cvesJsonData))
			if err != nil {
				fmt.Println("Error OSV-Scanner CVE marshalling JSON:", err)
				return
			}

			// Skip SSL verification as testing env
			if VANSEndpoint != "https://vans.nat.gov.tw" && VANSVersion != 1 {
				http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true} // #nosec G402
			}

			// Determine the data to marshal based on VANSVersion
			var jsonDataToSend []byte
			var marshalErr error
			if VANSVersion == 1 {
				jsonDataToSend, marshalErr = json.Marshal(VANSData)
			} else if VANSVersion == 2 {
				jsonDataToSend, marshalErr = json.Marshal(VANSV2Data)
			}

			// Check for marshalling error
			if marshalErr != nil {
				fmt.Println("Error marshalling JSON for VANS data:", marshalErr)
				return
			}

			// Debug print if enabled
			if DebugMode {
				fmt.Println("上傳 VANS", VANSVersion, "套件 JSON：")
				fmt.Println(string(jsonDataToSend))
			}

			// POST request
			makeHTTPPost(VANSAPIEndpoint, jsonDataToSend, VANSVersion)
		},
	}

	rootCmd.Flags().StringVarP(&SBOMInputPaths, "input-file", "i", "", "指定 SBOM 檔案目錄位置")
	rootCmd.Flags().StringVarP(&VANSKey, "vans-key", "k", "", "指定 VANS 機關資產管理 API key")
	rootCmd.Flags().StringVarP(&OId, "oid", "o", "", "機關 Object Identifier (OID)，可以至 OID 網站 https://oid.nat.gov.tw/OIDWeb/ 查詢")
	rootCmd.Flags().StringVarP(&UnitName, "unit-name", "u", "", "機關名稱，如：監察院")
	rootCmd.Flags().StringVarP(&VANSEndpoint, "vans-url", "", "https://vans.nat.gov.tw", "VANS API URL")
	rootCmd.Flags().StringVarP(&NVDKey, "nvd-key", "", "", "指定 NVD API key")
	rootCmd.Flags().StringVarP(&AssetGroupCode, "group", "g", "DEFAULT", "指定資產群組代碼")
	rootCmd.Flags().IntVarP(&VANSVersion, "vans-version", "", 2, "指定 VANS 版本（1 或 2）")
	rootCmd.Flags().BoolVarP(&DebugMode, "debug", "", false, "debug mode")

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

type VANSV2 struct {
	APIKey string       `json:"api_key"`
	Data   []VANSV2Item `json:"data"`
}

type VANSV2Item struct {
	OID            string `json:"oid"`        // v1 oid
	OrgName        string `json:"orgName"`    // v1 unit_name
	Identifier     string `json:"identifier"` // md5(mac address)
	AssetGroupCode string `json:"assetGroupCode"`
	AssetName      string `json:"assetName"` // v1 product_name
	Brand          string `json:"brand"`     // v1 product_vendor
	Version        string `json:"version"`   // v1 product_version
	CPE            string `json:"cpe"`       // v1 cpe23
	CPEName        string `json:"cpeName"`   // v1 product_name
}

func makeHTTPPost(VANSAPIEndpoint string, jsonData []byte, VANSVersion int) {
	// As we might assign the testing env URL as variable, therefore add the ignore lint for G107
	resp, err := http.Post(VANSAPIEndpoint, "application/json", bytes.NewBuffer(jsonData)) // #nosec G107
	fmt.Println("上傳至 VANS", VANSVersion, "中...")

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
	if input == "" {
		return ""
	}
	parts := strings.Split(input, "/")
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
			log.Fatal("NVDClient Error: ", err)
		}
		resp, err := nvdapi.GetCVEs(client, nvdapi.GetCVEsParams{
			CVEID: ptr(cve.CVE[0]),
		})
		if err != nil {
			// Maybe api key is invalid
			log.Fatal("NVDClient Error: ", err, " Please check if the NVD API key is valid.")
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
								log.Fatal("NVDClient Error: ", err)
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

func getIdentifier() string { // get mac address and hash with sha256
	interfaces, err := net.Interfaces()
	if err != nil {
		log.Fatal("MAC Address Error:", err)
	}

	var macAddress string
	for _, interf := range interfaces {
		if len(interf.HardwareAddr) > 0 {
			macAddress = interf.HardwareAddr.String()
			break
		}
	}

	if macAddress == "" {
		log.Fatal("No MAC address found")
	}

	fmt.Println("MAC Address:", macAddress)

	hash := sha256.Sum256([]byte(macAddress))
	sha256String := hex.EncodeToString(hash[:])
	return sha256String
}

func isDuplicate(data []VANSV2Item, assetName string) bool {
	for _, item := range data {
		if item.AssetName == assetName {
			return true
		}
	}
	return false
}

func replaceOrAppend(data []VANSV2Item, newData VANSV2Item) []VANSV2Item {
	for i, item := range data {
		if item.AssetName == newData.AssetName {
			data[i] = newData
			return data
		}
	}
	return append(data, newData)
}
