package filehandler

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"math/rand"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/seabasssec/cvereporter/internal/structures"
	"github.com/xuri/excelize/v2"
)

// Using for generation random string
func RandStringRunes(n int) string {
	var letterRunes = []rune("1234567890")
	rand.Seed(time.Now().UnixNano())
	b := make([]rune, n)
	for i := range b {
		b[i] = letterRunes[rand.Intn(len(letterRunes))]
	}
	return string(b)
}

func CheckActualy(year string) error {
	reqCrtErr := errors.New("could not create request in CheckActualy")
	reqMknErr := errors.New("could not make request in CheckActualy")

	requestURL := fmt.Sprintf("https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-%s.meta", year)
	filename := fmt.Sprintf("nvdcve-1.1-%s.json", year)

	req, err := http.NewRequest(http.MethodGet, requestURL, nil)
	if err != nil {
		return reqCrtErr
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return reqMknErr
	}
	defer resp.Body.Close()

	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() {
		txtline := scanner.Bytes()
		if bytes.Equal(txtline[:6], []byte("sha256")) {
			if _, err := os.Stat(filename); errors.Is(err, os.ErrNotExist) {
				err := GetAndExtractGz(year)
				if err != nil {
					return err
				}
				return nil
			}
			f, err := os.Open(filename)
			if err != nil {
				return err
			}
			defer f.Close()

			h := sha256.New()
			if _, err := io.Copy(h, f); err != nil {
				return err
			}
			if string(txtline[7:]) != strings.ToUpper(hex.EncodeToString(h.Sum(nil))) {
				fmt.Printf("sha256 for file %s from NVD-server is: %s \n", filename, string(txtline[7:]))
				fmt.Printf("sha256 from local storage file %s is: %s \n", filename, strings.ToUpper(hex.EncodeToString(h.Sum(nil))))
				fmt.Printf("Update file %s from NVD-server\n", filename)
				err := GetAndExtractGz(year)
				if err != nil {
					fmt.Printf("Error file %s upadate process\n", filename)
					return err
				}
			}
		}
	}
	return nil
}

func GetAndExtractGz(year string) error {
	// Define error
	reqCrtErr := errors.New("could not create request in GetAndExtractGz")
	reqMknErr := errors.New("could not make request in GetAndExtractGz")
	cpyDataErr := errors.New("error copy data to file")
	// This for local testing
	//requestURL := fmt.Sprintf("http://127.0.0.1:8000/nvdcve-1.1-%s.json.gz", year)
	filename := fmt.Sprintf("nvdcve-1.1-%s.json.gz", year)
	requestURL := fmt.Sprintf("https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-%s.json.gz", year)

	out, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer out.Close()

	req, err := http.NewRequest(http.MethodGet, requestURL, nil)
	if err != nil {
		return reqCrtErr
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return reqMknErr
	}
	defer resp.Body.Close()

	_, err = io.Copy(out, resp.Body)
	if err != nil {
		return cpyDataErr
	}
	// Create json from gz

	gzipFile, err := os.OpenFile(filename, os.O_RDONLY|os.O_CREATE, 0644)
	if err != nil {
		return err
	}

	// Create a new gzip reader
	gzipReader, err := gzip.NewReader(gzipFile)
	if err != nil {
		return err
	}
	defer gzipReader.Close()

	outfileWriter, err := os.Create(fmt.Sprintf("./nvdcve-1.1-%s.json", year))
	if err != nil {
		return err
	}
	defer outfileWriter.Close()

	_, err = io.Copy(outfileWriter, gzipReader)
	if err != nil {
		return err
	}

	return nil
}

func CreateReport(years []string, part string, vendor string, product string, version string, update string, edition string, language string, sw_edition string, target_sw string, target_hw string, other string) (string, error) {
	f := excelize.NewFile()
	defer f.Close()
	for _, year := range years {
		var rows []structures.ReportRow
		sheet := year
		index, err := f.NewSheet(sheet)
		if err != nil {
			return "", err
		}

		f.SetCellValue(sheet, "A1", "Идентификатор CVE")
		f.SetCellValue(sheet, "B1", "CPE 2.3")
		f.SetCellValue(sheet, "C1", "Дата публикации")
		f.SetCellValue(sheet, "D1", "Базовый индекс CVSS3")
		f.SetCellValue(sheet, "E1", "Важность CVSS3")
		f.SetCellValue(sheet, "F1", "CVSS3 Вектор атаки")
		f.SetCellValue(sheet, "G1", "Базовый индекс CVSS2")
		f.SetCellValue(sheet, "H1", "Важность CVSS2")
		f.SetCellValue(sheet, "I1", "CVSS2 Вектор атаки")
		f.SetCellValue(sheet, "J1", "Влияние")
		f.SetCellValue(sheet, "K1", "Общедоступный эксплоит")
		f.SetCellValue(sheet, "L1", "Описание")

		// For reports with English column headings
		// f.SetCellValue(sheet, "A1", "CVE ID")
		// f.SetCellValue(sheet, "B1", "CPE 2.3 version")
		// f.SetCellValue(sheet, "C1", "Date of publication")
		// f.SetCellValue(sheet, "D1", "Base score")
		// f.SetCellValue(sheet, "E1", "Severity")
		// f.SetCellValue(sheet, "F1", "CVSS3 Attack vector")
		// f.SetCellValue(sheet, "G1", "Base score")
		// f.SetCellValue(sheet, "H1", "Severity")
		// f.SetCellValue(sheet, "I1", "CVSS3 Attack vector")
		// f.SetCellValue(sheet, "J1", "Impact")
		// f.SetCellValue(sheet, "K1", "Available exploit")
		// f.SetCellValue(sheet, "L1", "Description")
		f.SetActiveSheet(index)

		filename := fmt.Sprintf("./nvdcve-1.1-%s.json", year)

		file, err := os.Open(filename)
		if err != nil {
			return "", err
		}
		byteValue, err := ioutil.ReadAll(file)
		if err != nil {
			return "", err
		}

		var jsonfile structures.JSONcommonDataStructure
		json.Unmarshal(byteValue, &jsonfile)

		dataset := jsonfile.CVEItems
		for _, data := range dataset {
			// var row structures.ReportRow
			row2 := data.Configurations.Nodes
			for _, z := range row2 {
				row31 := z.CPEMatch
				row3 := z.Children
				for _, y := range row3 {
					// Parse first row Children
					row4 := y.CPEMatch
					for _, x := range row4 {
						if x.Vulnerable &&
							strings.Split(x.CPE23Uri, ":")[2] == part &&
							strings.Split(x.CPE23Uri, ":")[3] == vendor &&
							strings.Split(x.CPE23Uri, ":")[4] == product &&
							((strings.HasPrefix(strings.Split(x.CPE23Uri, ":")[5], version) || // If version is determined or all version or version is not used
								strings.Split(x.CPE23Uri, ":")[5] == "-" ||
								strings.Split(x.CPE23Uri, ":")[5] == "*") ||
								strings.Split(x.CPE23Uri, ":")[5] != "" && version == "") && // If field version is empty
							((strings.HasPrefix(strings.Split(x.CPE23Uri, ":")[6], edition) || // If edition is determined or all version or version is not used
								strings.Split(x.CPE23Uri, ":")[6] == "-" ||
								strings.Split(x.CPE23Uri, ":")[6] == "*") ||
								strings.Split(x.CPE23Uri, ":")[6] != "" && edition == "") && // If edition version is empty
							((strings.Split(x.CPE23Uri, ":")[11] == target_hw || // If arch is determined or all arch or arch is not used
								strings.Split(x.CPE23Uri, ":")[11] == "*" ||
								strings.Split(x.CPE23Uri, ":")[11] == "-") ||
								strings.Split(x.CPE23Uri, ":")[11] != "" && target_hw == "") { // If field arch is empty

							impactString := ""
							exploitIs := ""
							for _, ref := range data.CVE.References.ReferencesData {
								if ref.Refsource != "" || ref.Url != "" {
									count := 0
									// Check our refs if contain info about exploit
									// This info should't include to resf category
									for _, v := range ref.Tags {
										if v == "Exploit" {
											count++
										}
										if v == "Patch" {
											count--
										}
									}
									if count <= 0 {
										impactString += fmt.Sprintf("\n%s", ref.Url)
									}
								}
								for _, tag := range ref.Tags {
									if tag == "Exploit" {
										exploitIs += fmt.Sprintf("%s\n", ref.Url)
									}
								}
								// if ref.Name != "" {
								// 	impactString = ref.Name
								// } else if ref.Url != "" {
								// 	impactString = ref.Url
								// }
							}
							if impactString != "" {
								impactString = "Есть патч или рекомендации по устранению для данной уязвимости. " + impactString
							}
							if exploitIs == "" {
								exploitIs = "Нет данных"
							}
							if impactString == "" {
								impactString = "Нет данных"
							}

							row := structures.ReportRow{
								CVEID:           data.CVE.DataMeta.ID,
								CPE23:           x.CPE23Uri,
								DatePublication: data.PublishedDate,
								BaseScoreCVSS3:  data.Impact.BaseMetricV3.CVSSV3.BaseScore,
								SeverityCVSS3:   data.Impact.BaseMetricV3.CVSSV3.BaseSeverity,
								CVSS3Vector:     data.Impact.BaseMetricV3.CVSSV3.VectorString,
								BaseScoreCVSS2:  data.Impact.BaseMetricV2.CVSSV2.BaseScore,
								SeverityCVSS2:   data.Impact.BaseMetricV2.Severity,
								CVSS2Vector:     data.Impact.BaseMetricV2.CVSSV2.VectorString,
								Impact:          impactString,
								Exploit:         exploitIs,
								Description:     data.CVE.DataDescription.DescriptionData[0].Value,
							}
							rows = append(rows, row)
						}
					}
				}
				// Parse nested row Children
				for _, r := range row31 {
					if r.Vulnerable &&
						strings.Split(r.CPE23Uri, ":")[2] == part &&
						strings.Split(r.CPE23Uri, ":")[3] == vendor &&
						strings.Split(r.CPE23Uri, ":")[4] == product &&
						((strings.HasPrefix(strings.Split(r.CPE23Uri, ":")[5], version) || // If version is determined or all version or version is not used
							strings.Split(r.CPE23Uri, ":")[5] == "-" ||
							strings.Split(r.CPE23Uri, ":")[5] == "*") ||
							strings.Split(r.CPE23Uri, ":")[5] != "" && version == "") && // If field version is empty
						((strings.HasPrefix(strings.Split(r.CPE23Uri, ":")[6], edition) || // If edition is determined or all version or version is not used
							strings.Split(r.CPE23Uri, ":")[6] == "-" ||
							strings.Split(r.CPE23Uri, ":")[6] == "*") ||
							strings.Split(r.CPE23Uri, ":")[6] != "" && edition == "") && // If edition version is empty
						((strings.Split(r.CPE23Uri, ":")[11] == target_hw || // If arch is determined or all arch or arch is not used
							strings.Split(r.CPE23Uri, ":")[11] == "*" ||
							strings.Split(r.CPE23Uri, ":")[11] == "-") ||
							strings.Split(r.CPE23Uri, ":")[11] != "" && target_hw == "") { // If field arch is empty
						impactString := ""
						exploitIs := ""
						for _, ref := range data.CVE.References.ReferencesData {
							if ref.Refsource != "" || ref.Url != "" {
								count := 0
								// Check our refs if contain info about exploit
								// This info should't include to resf category
								for _, v := range ref.Tags {
									if v == "Exploit" {
										count++
									}
									if v == "Patch" {
										count--
									}
								}
								if count <= 0 {
									impactString += fmt.Sprintf("\n%s", ref.Url)
								}
							}
							for _, tag := range ref.Tags {
								if tag == "Exploit" {
									exploitIs += fmt.Sprintf("%s\n", ref.Url)
								}
							}
						}
						if impactString != "" {
							impactString = "Есть патч или рекомендации по устранению для данной уязвимости." + impactString
						}
						if exploitIs == "" {
							exploitIs = "Нет данных"
						}
						if impactString == "" {
							impactString = "Нет данных"
						}

						row := structures.ReportRow{
							CVEID:           data.CVE.DataMeta.ID,
							CPE23:           r.CPE23Uri,
							DatePublication: data.PublishedDate,
							BaseScoreCVSS3:  data.Impact.BaseMetricV3.CVSSV3.BaseScore,
							SeverityCVSS3:   data.Impact.BaseMetricV3.CVSSV3.BaseSeverity,
							CVSS3Vector:     data.Impact.BaseMetricV3.CVSSV3.VectorString,
							BaseScoreCVSS2:  data.Impact.BaseMetricV2.CVSSV2.BaseScore,
							SeverityCVSS2:   data.Impact.BaseMetricV2.Severity,
							CVSS2Vector:     data.Impact.BaseMetricV2.CVSSV2.VectorString,
							Impact:          impactString,
							Exploit:         exploitIs,
							Description:     data.CVE.DataDescription.DescriptionData[0].Value,
						}
						rows = append(rows, row)
					}
				}
			}
		}
		for k, v := range rows {
			f.SetCellValue(sheet, "A"+strconv.Itoa(k+2), v.CVEID)
			f.SetCellValue(sheet, "B"+strconv.Itoa(k+2), v.CPE23)
			f.SetCellValue(sheet, "C"+strconv.Itoa(k+2), v.DatePublication)
			f.SetCellValue(sheet, "D"+strconv.Itoa(k+2), v.BaseScoreCVSS3)
			f.SetCellValue(sheet, "E"+strconv.Itoa(k+2), v.SeverityCVSS3)
			f.SetCellValue(sheet, "F"+strconv.Itoa(k+2), v.CVSS3Vector)
			f.SetCellValue(sheet, "G"+strconv.Itoa(k+2), v.BaseScoreCVSS2)
			f.SetCellValue(sheet, "H"+strconv.Itoa(k+2), v.SeverityCVSS2)
			f.SetCellValue(sheet, "I"+strconv.Itoa(k+2), v.CVSS2Vector)
			f.SetCellValue(sheet, "J"+strconv.Itoa(k+2), v.Impact)
			f.SetCellValue(sheet, "K"+strconv.Itoa(k+2), v.Exploit)
			f.SetCellValue(sheet, "L"+strconv.Itoa(k+2), v.Description)
		}
	}
	randomseed := RandStringRunes(5)
	// Save spreadsheet by the given path.
	xlsxFileName := fmt.Sprintf("/public/%s_%s_%s_%s_%s_%s_%s.xlsx", vendor, product, version, edition, target_hw, years, randomseed)
	if err := f.SaveAs("." + xlsxFileName); err != nil {
		fmt.Println(err)
	}
	return "http://127.0.0.1:8080" + xlsxFileName, nil
}
