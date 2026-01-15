package sbom

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	domainsbom "github.com/felixgeelhaar/verdictsec/internal/domain/sbom"
)

// SPDXDocument represents an SPDX 2.3 document.
type SPDXDocument struct {
	SPDXID                   string             `json:"SPDXID"`
	SPDXVersion              string             `json:"spdxVersion"`
	CreationInfo             SPDXCreationInfo   `json:"creationInfo"`
	Name                     string             `json:"name"`
	DataLicense              string             `json:"dataLicense"`
	DocumentNamespace        string             `json:"documentNamespace"`
	DocumentDescribes        []string           `json:"documentDescribes,omitempty"`
	Packages                 []SPDXPackage      `json:"packages,omitempty"`
	Files                    []SPDXFile         `json:"files,omitempty"`
	Relationships            []SPDXRelationship `json:"relationships,omitempty"`
	ExternalDocumentRefs     []SPDXExtDocRef    `json:"externalDocumentRefs,omitempty"`
	ExtractedLicensingInfos  []SPDXLicenseInfo  `json:"hasExtractedLicensingInfos,omitempty"`
}

// SPDXCreationInfo contains creation metadata.
type SPDXCreationInfo struct {
	Created            string   `json:"created"`
	Creators           []string `json:"creators"`
	LicenseListVersion string   `json:"licenseListVersion,omitempty"`
	Comment            string   `json:"comment,omitempty"`
}

// SPDXPackage represents an SPDX package.
type SPDXPackage struct {
	SPDXID               string                 `json:"SPDXID"`
	Name                 string                 `json:"name"`
	VersionInfo          string                 `json:"versionInfo,omitempty"`
	PackageFileName      string                 `json:"packageFileName,omitempty"`
	Supplier             string                 `json:"supplier,omitempty"`
	Originator           string                 `json:"originator,omitempty"`
	DownloadLocation     string                 `json:"downloadLocation"`
	FilesAnalyzed        bool                   `json:"filesAnalyzed"`
	PackageVerificationCode *SPDXVerificationCode `json:"packageVerificationCode,omitempty"`
	Checksums            []SPDXChecksum         `json:"checksums,omitempty"`
	Homepage             string                 `json:"homepage,omitempty"`
	SourceInfo           string                 `json:"sourceInfo,omitempty"`
	LicenseConcluded     string                 `json:"licenseConcluded,omitempty"`
	LicenseInfoFromFiles []string               `json:"licenseInfoFromFiles,omitempty"`
	LicenseDeclared      string                 `json:"licenseDeclared,omitempty"`
	LicenseComments      string                 `json:"licenseComments,omitempty"`
	CopyrightText        string                 `json:"copyrightText,omitempty"`
	Summary              string                 `json:"summary,omitempty"`
	Description          string                 `json:"description,omitempty"`
	Comment              string                 `json:"comment,omitempty"`
	ExternalRefs         []SPDXExternalRef      `json:"externalRefs,omitempty"`
	AttributionTexts     []string               `json:"attributionTexts,omitempty"`
	PrimaryPackagePurpose string                `json:"primaryPackagePurpose,omitempty"`
	ReleaseDate          string                 `json:"releaseDate,omitempty"`
	BuiltDate            string                 `json:"builtDate,omitempty"`
	ValidUntilDate       string                 `json:"validUntilDate,omitempty"`
}

// SPDXVerificationCode is the package verification code.
type SPDXVerificationCode struct {
	PackageVerificationCodeValue         string   `json:"packageVerificationCodeValue"`
	PackageVerificationCodeExcludedFiles []string `json:"packageVerificationCodeExcludedFiles,omitempty"`
}

// SPDXChecksum represents a checksum.
type SPDXChecksum struct {
	Algorithm     string `json:"algorithm"`
	ChecksumValue string `json:"checksumValue"`
}

// SPDXExternalRef represents an external reference.
type SPDXExternalRef struct {
	ReferenceCategory string `json:"referenceCategory"`
	ReferenceType     string `json:"referenceType"`
	ReferenceLocator  string `json:"referenceLocator"`
	Comment           string `json:"comment,omitempty"`
}

// SPDXFile represents an SPDX file.
type SPDXFile struct {
	SPDXID             string         `json:"SPDXID"`
	FileName           string         `json:"fileName"`
	Checksums          []SPDXChecksum `json:"checksums,omitempty"`
	LicenseConcluded   string         `json:"licenseConcluded,omitempty"`
	LicenseInfoInFiles []string       `json:"licenseInfoInFiles,omitempty"`
	CopyrightText      string         `json:"copyrightText,omitempty"`
	Comment            string         `json:"comment,omitempty"`
	FileTypes          []string       `json:"fileTypes,omitempty"`
}

// SPDXRelationship represents a relationship between elements.
type SPDXRelationship struct {
	SPDXElementID      string `json:"spdxElementId"`
	RelationshipType   string `json:"relationshipType"`
	RelatedSPDXElement string `json:"relatedSpdxElement"`
	Comment            string `json:"comment,omitempty"`
}

// SPDXExtDocRef represents an external document reference.
type SPDXExtDocRef struct {
	ExternalDocumentID string       `json:"externalDocumentId"`
	Checksum           SPDXChecksum `json:"checksum"`
	SPDXDocument       string       `json:"spdxDocument"`
}

// SPDXLicenseInfo represents extracted licensing information.
type SPDXLicenseInfo struct {
	LicenseID           string   `json:"licenseId"`
	ExtractedText       string   `json:"extractedText"`
	Name                string   `json:"name,omitempty"`
	CrossRefs           []string `json:"crossRefs,omitempty"`
	Comment             string   `json:"comment,omitempty"`
}

// SPDXParser parses SPDX documents.
type SPDXParser struct{}

// NewSPDXParser creates a new SPDX parser.
func NewSPDXParser() *SPDXParser {
	return &SPDXParser{}
}

// ParseDocument parses SPDX JSON data.
func (p *SPDXParser) ParseDocument(data []byte) (*SPDXDocument, error) {
	var doc SPDXDocument
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("failed to parse SPDX JSON: %w", err)
	}
	return &doc, nil
}

// ToSBOM converts an SPDX document to domain SBOM.
func (p *SPDXParser) ToSBOM(doc *SPDXDocument) (*domainsbom.SBOM, error) {
	if doc == nil {
		return nil, fmt.Errorf("nil SPDX document")
	}

	// Convert packages to components
	components := make([]domainsbom.Component, 0, len(doc.Packages))
	for _, pkg := range doc.Packages {
		// Skip the document's root package if it describes the analyzed project
		if pkg.SPDXID == "SPDXRef-DOCUMENT" || pkg.SPDXID == "SPDXRef-RootPackage" {
			continue
		}

		// Extract PURL from external refs
		purl := ""
		for _, ref := range pkg.ExternalRefs {
			if ref.ReferenceType == "purl" || ref.ReferenceCategory == "PACKAGE-MANAGER" {
				purl = ref.ReferenceLocator
				break
			}
		}

		// Determine license
		license := pkg.LicenseConcluded
		if license == "" || license == "NOASSERTION" {
			license = pkg.LicenseDeclared
		}
		if license == "NOASSERTION" {
			license = ""
		}

		// Determine type from purpose
		typ := "library"
		if pkg.PrimaryPackagePurpose != "" {
			typ = strings.ToLower(pkg.PrimaryPackagePurpose)
		}

		// Detect language from PURL or supplier info
		language := detectLanguageFromPURL(purl)

		comp := domainsbom.NewComponentFull(
			pkg.Name,
			pkg.VersionInfo,
			purl,
			license,
			language,
			typ,
		)
		components = append(components, comp)
	}

	// Parse timestamp
	var timestamp time.Time
	if doc.CreationInfo.Created != "" {
		t, err := time.Parse(time.RFC3339, doc.CreationInfo.Created)
		if err == nil {
			timestamp = t
		}
	}
	if timestamp.IsZero() {
		timestamp = time.Now()
	}

	// Extract tool info from creators
	toolName := "unknown"
	toolVer := ""
	for _, creator := range doc.CreationInfo.Creators {
		if strings.HasPrefix(creator, "Tool:") {
			parts := strings.SplitN(strings.TrimPrefix(creator, "Tool:"), "-", 2)
			toolName = strings.TrimSpace(parts[0])
			if len(parts) > 1 {
				toolVer = strings.TrimSpace(parts[1])
			}
			break
		}
	}

	return domainsbom.NewSBOMFull(
		domainsbom.FormatSPDX,
		doc.Name,
		"module",
		components,
		timestamp,
		toolName,
		toolVer,
	), nil
}

// detectLanguageFromPURL attempts to detect the programming language from a PURL.
func detectLanguageFromPURL(purl string) string {
	if purl == "" {
		return ""
	}

	// Package URL format: pkg:<type>/<namespace>/<name>@<version>
	if strings.HasPrefix(purl, "pkg:golang/") {
		return "go"
	}
	if strings.HasPrefix(purl, "pkg:npm/") {
		return "javascript"
	}
	if strings.HasPrefix(purl, "pkg:pypi/") {
		return "python"
	}
	if strings.HasPrefix(purl, "pkg:maven/") {
		return "java"
	}
	if strings.HasPrefix(purl, "pkg:cargo/") {
		return "rust"
	}
	if strings.HasPrefix(purl, "pkg:nuget/") {
		return "csharp"
	}
	if strings.HasPrefix(purl, "pkg:gem/") {
		return "ruby"
	}
	if strings.HasPrefix(purl, "pkg:composer/") {
		return "php"
	}

	return ""
}
