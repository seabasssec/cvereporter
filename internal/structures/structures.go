package structures

//5 Level-----------------------------------------------------------------------------------

type ProblemDescription struct {
	Lang  string `json:"lang"`
	Value string `json:"value"`
}

type CPEName struct {
	CPE23Uri         string `json:"cpe23Uri,omitempty"`
	CPE22Uri         string `json:"cpe22Uri,omitempty"`
	LastModifiedDate string `json:"lastModifiedDate,omitempty"`
}

//4 Level-----------------------------------------------------------------------------------

type ProblemtypeData struct {
	ProblemDescription []ProblemDescription `json:"description"`
}

type ReferencesData struct {
	Url       string   `json:"url"`
	Name      string   `json:"name"`
	Refsource string   `json:"refsource"`
	Tags      []string `json:"tags"`
}

type DescriptionData struct {
	Lang  string `json:"lang"`
	Value string `json:"value"`
}

type CPEMatch struct {
	Vulnerable            bool      `json:"vulnerable,omitempty"`
	CPE23Uri              string    `json:"cpe23Uri,omitempty"`
	CPE22Uri              string    `json:"cpe22Uri,omitempty"`
	VersionStartExcluding string    `json:"versionStartExcluding,omitempty"`
	VersionStartIncluding string    `json:"versionStartIncluding,omitempty"`
	VersionEndExcluding   string    `json:"versionEndExcluding,omitempty"`
	VersionEndIncluding   string    `json:"versionEndIncluding,omitempty"`
	CPEName               []CPEName `json:"cpe_name,omitempty"`
}

type CVSSV3 struct {
	Version               string  `json:"version,omitempty"`
	VectorString          string  `json:"vectorString,omitempty"`
	AttackVector          string  `json:"attackVector,omitempty"`
	AttackComplexity      string  `json:"attackComplexity,omitempty"`
	PrivilegesRequired    string  `json:"privilegesRequired,omitempty"`
	UserInteraction       string  `json:"userInteraction,omitempty"`
	Scope                 string  `json:"scope,omitempty"`
	ConfidentialityImpact string  `json:"confidentialityImpact,omitempty"`
	IntegrityImpact       string  `json:"integrityImpact,omitempty"`
	AvailabilityImpact    string  `json:"availabilityImpact,omitempty"`
	BaseScore             float64 `json:"baseScore,omitempty"`
	BaseSeverity          string  `json:"baseSeverity,omitempty"`
}

type CVSSV2 struct {
	Version               string  `json:"version,omitempty"`
	VectorString          string  `json:"vectorString,omitempty"`
	AccessVector          string  `json:"accessVector,omitempty"`
	AccessComplexity      string  `json:"accessComplexity,omitempty"`
	Authentication        string  `json:"authentication,omitempty"`
	ConfidentialityImpact string  `json:"confidentialityImpact,omitempty"`
	IntegrityImpact       string  `json:"integrityImpact,omitempty"`
	AvailabilityImpact    string  `json:"availabilityImpact,omitempty"`
	BaseScore             float64 `json:"baseScore,omitempty"`
}

//3 Level-----------------------------------------------------------------------------------

type DataMeta struct {
	ID       string `json:"ID"`
	ASSIGNER string `json:"ASSIGNER,omitempty"`
}

type Problemtype struct {
	ProblemtypeData []ProblemtypeData `json:"problemtype_data,omitempty"`
}

type References struct {
	ReferencesData []ReferencesData `json:"reference_data,omitempty"`
}

type DataDescription struct {
	DescriptionData []DescriptionData `json:"description_data,omitempty"`
}

type Nodes struct {
	Operator string     `json:"operator,omitempty"`
	Children []Nodes    `json:"children,omitempty"`
	CPEMatch []CPEMatch `json:"cpe_match,omitempty"`
}

type BaseMetricV3 struct {
	CVSSV3             CVSSV3  `json:"cvssV3,omitempty"`
	ExploitabiltyScore float64 `json:"exploitabilityScore,omitempty"`
	ImpactScore        float64 `json:"impactScore,omitempty"`
}

type BaseMetricV2 struct {
	CVSSV2                  CVSSV2  `json:"cvssV2,omitempty"`
	Severity                string  `json:"severity,omitempty"`
	ExploitabiltyScore      float64 `json:"exploitabilityScore,omitempty"`
	ImpactScore             float64 `json:"impactScore,omitempty"`
	AcInsufInfo             bool    `json:"acInsufInfo,omitempty"`
	ObtainAllPrivilege      bool    `json:"obtainAllPrivilege,omitempty"`
	ObtainUserPrivilege     bool    `json:"obtainUserPrivilege,omitempty"`
	ObtainOtherPrivilege    bool    `json:"obtainOtherPrivilege,omitempty"`
	UserInteractionRequired bool    `json:"userInteractionRequired,omitempty"`
}

//2 Level-----------------------------------------------------------------------------------

type CVE struct {
	DataType        string          `json:"data_type"`
	DataFormat      string          `json:"data_format"`
	DataVersion     string          `json:"data_version"`
	DataMeta        DataMeta        `json:"CVE_data_meta"`
	Problemtype     Problemtype     `json:"problemtype"`
	References      References      `json:"references"`
	DataDescription DataDescription `json:"description"`
}

type Configurations struct {
	CVEDataVersion string  `json:"CVE_data_version"`
	Nodes          []Nodes `json:"nodes,omitempty"`
}

type Impact struct {
	BaseMetricV3 BaseMetricV3 `json:"baseMetricV3,omitempty"`
	BaseMetricV2 BaseMetricV2 `json:"baseMetricV2,omitempty"`
}

//1 Level------------------------------------------------------------------------------------

type CVEItems struct {
	CVE              CVE            `json:"cve"`
	Configurations   Configurations `json:"configurations,omitempty"`
	Impact           Impact         `json:"impact,omitempty"`
	PublishedDate    string         `json:"publishedDate,omitempty"`
	LastModifiedDate string         `json:"lastModifiedDate,omitempty"`
}

//0 Level-----------------------------------------------------------------------------------

type JSONcommonDataStructure struct {
	CVEDataType         string     `json:"CVE_data_type"`
	CVEDataFormat       string     `json:"CVE_data_format"`
	CVEDataVersion      string     `json:"CVE_data_version"`
	CVEDataNumberOfCVEs string     `json:"CVE_data_numberOfCVEs"`
	CVEDataTimestamp    string     `json:"CVE_data_timestamp"`
	CVEItems            []CVEItems `json:"CVE_Items"`
}

// Structure for report row

type ReportRow struct {
	CVEID           string
	CPE23           string
	DatePublication string
	BaseScoreCVSS3  float64
	SeverityCVSS3   string
	CVSS3Vector     string
	BaseScoreCVSS2  float64
	SeverityCVSS2   string
	CVSS2Vector     string
	Impact          string
	Exploit         string
	Description     string
}

type JSONReportRequest struct {
	FromYear  string `json:"first"`
	ToYear    string `json:"last"`
	Part      string `json:"part"`
	Vendor    string `json:"vendor"`
	Product   string `json:"product"`
	Version   string `json:"version"`
	Update    string `json:"update"`
	Edition   string `json:"edition"`
	Language  string `json:"language"`
	SWEdition string `json:"sw_edition"`
	TargetSW  string `json:"target_sw"`
	TargetHW  string `json:"target_hw"`
	Other     string `json:"other"`
}

type JSONUpdateDB struct {
	FromYear string `json:"first"`
	ToYear   string `json:"last"`
}
