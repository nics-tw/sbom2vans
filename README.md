# sbom2vans

此工具協助轉換 SBOM 文件符合 VANS 格式，透過 [OSV scanner](https://github.com/google/osv-scanner) 查詢資料庫確認組件是否有已知的安全漏洞，並使用 NVD API 查詢已知漏洞對應 CPE 格式，最後將 SBOM 內套件轉轉換符合 VANS 格式欄位進行上傳。

## Usage

```
$ ./sbom2vans -h
SBOM 轉換為 VANS 機關資產管理 CLI 工具

Usage:
  sbom2vans [flags]

Flags:
  -h, --help                help for sbom2vans
  -i, --input-file string   指定 SBOM 檔案目錄位置
      --oid string          機關 Object Identifier (OID)，可以至 OID 網站 https://oid.nat.gov.tw/OIDWeb/ 查詢
  -u, --unit-name string    機關名稱，如：監察院
  -k, --vans-key string     指定 VANS 機關資產管理 API key
```