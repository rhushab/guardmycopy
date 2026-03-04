package core

type Severity string

const (
	SeverityLow    Severity = "low"
	SeverityMedium Severity = "medium"
	SeverityHigh   Severity = "high"
)

const (
	FindingTypePEMPrivateKey    = "pem_private_key"
	FindingTypeJWT              = "jwt"
	FindingTypeEnvSecret        = "env_secret"
	FindingTypeHighEntropyToken = "high_entropy_token"
)

type RiskLevel string

const (
	RiskLevelLow  RiskLevel = "low"
	RiskLevelMed  RiskLevel = "med"
	RiskLevelHigh RiskLevel = "high"
)

type Finding struct {
	Type     string
	Severity Severity
	Start    int
	End      int
	Label    string
}

type Detector interface {
	Detect(text string) []Finding
}

type Redactor interface {
	Redact(text string, findings []Finding) string
}

type ScanResult struct {
	Findings  []Finding
	Score     int
	RiskLevel RiskLevel
}

type SanitizeResult struct {
	SanitizedText string
	Findings      []Finding
	Score         int
	RiskLevel     RiskLevel
}
