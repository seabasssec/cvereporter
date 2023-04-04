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
	"net/http"
	"os"
	"strconv"
	"strings"

	"github.com/seabasssec/cvereporter/internal/structures"
	"github.com/xuri/excelize/v2"
)

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
			fmt.Printf("sha256 for file %s from NVD-server is: %s \n", filename, string(txtline[7:]))
			fmt.Printf("sha256 from local storage file %s is: %s \n", filename, strings.ToUpper(hex.EncodeToString(h.Sum(nil))))
			if string(txtline[7:]) != strings.ToUpper(hex.EncodeToString(h.Sum(nil))) {
				err := GetAndExtractGz(year)
				if err != nil {
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

func CreateReport(years []string, part string, vendor string, component string, version string, arch string) error {
	f := excelize.NewFile()
	defer f.Close()
	for _, year := range years {
		var rows []structures.ReportRow
		sheet := year
		index, err := f.NewSheet(sheet)
		if err != nil {
			return err
		}

		f.SetCellValue(sheet, "A1", "CVE ID")
		f.SetCellValue(sheet, "B1", "CPE 2.3 version")
		f.SetCellValue(sheet, "C1", "Date of publication")
		f.SetCellValue(sheet, "D1", "Base score")
		f.SetCellValue(sheet, "E1", "Severity")
		f.SetCellValue(sheet, "F1", "Attack vector")
		f.SetCellValue(sheet, "G1", "Impact")
		f.SetCellValue(sheet, "H1", "Description")
		f.SetActiveSheet(index)

		filename := fmt.Sprintf("./nvdcve-1.1-%s.json", year)

		file, err := os.Open(filename)
		if err != nil {
			return err
		}
		byteValue, err := ioutil.ReadAll(file)
		if err != nil {
			return err
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
							strings.Split(x.CPE23Uri, ":")[4] == component &&
							((strings.Split(x.CPE23Uri, ":")[5] == version || // If version is determined or all version or version is not used
								strings.Split(x.CPE23Uri, ":")[5] == "-" ||
								strings.Split(x.CPE23Uri, ":")[5] == "*") ||
								strings.Split(x.CPE23Uri, ":")[5] != "" && version == "") && // If field version is empty
							((strings.Split(x.CPE23Uri, ":")[11] == arch || // If arch is determined or all arch or arch is not used
								strings.Split(x.CPE23Uri, ":")[11] == "*" ||
								strings.Split(x.CPE23Uri, ":")[11] == "-") ||
								strings.Split(x.CPE23Uri, ":")[11] != "" && arch == "") { // If field arch is empty

							impactString := ""
							if strings.Split(x.CPE23Uri, ":")[6] == "*" || // To fill in the "Impact" field
								(strings.Split(x.CPE23Uri, ":")[6] != "" &&
									strings.Split(x.CPE23Uri, ":")[6] != "-" &&
									strings.Split(x.CPE23Uri, ":")[6] != "*") {
								impactString = fmt.Sprintf("Not vulnerable. There is an update %s", strings.Split(x.CPE23Uri, ":")[6])
							}
							row := structures.ReportRow{
								CVEID:           data.CVE.DataMeta.ID,
								CPE23:           x.CPE23Uri,
								DatePublication: data.PublishedDate,
								BaseScore:       data.Impact.BaseMetricV3.CVSSV3.BaseScore,
								Severity:        data.Impact.BaseMetricV3.CVSSV3.BaseSeverity,
								CVSSVector:      data.Impact.BaseMetricV3.CVSSV3.VectorString,
								Impact:          impactString,
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
						strings.Split(r.CPE23Uri, ":")[4] == component &&
						((strings.Split(r.CPE23Uri, ":")[5] == version || // If version is determined or all version or version is not used
							strings.Split(r.CPE23Uri, ":")[5] == "-" ||
							strings.Split(r.CPE23Uri, ":")[5] == "*") ||
							strings.Split(r.CPE23Uri, ":")[5] != "" && version == "") && // If field version is empty
						((strings.Split(r.CPE23Uri, ":")[11] == arch || // If arch is determined or all arch or arch is not used
							strings.Split(r.CPE23Uri, ":")[11] == "*" ||
							strings.Split(r.CPE23Uri, ":")[11] == "-") ||
							strings.Split(r.CPE23Uri, ":")[11] != "" && arch == "") { // If field arch is empty
						impactString := ""
						if strings.Split(r.CPE23Uri, ":")[6] == "*" || // To fill in the "Impact" field
							(strings.Split(r.CPE23Uri, ":")[6] != "" &&
								strings.Split(r.CPE23Uri, ":")[6] != "-" &&
								strings.Split(r.CPE23Uri, ":")[6] != "*") {
							impactString = fmt.Sprintf("Not vulnerable. There is an update %s", strings.Split(r.CPE23Uri, ":")[6])
						}

						row := structures.ReportRow{
							CVEID:           data.CVE.DataMeta.ID,
							CPE23:           r.CPE23Uri,
							DatePublication: data.PublishedDate,
							BaseScore:       data.Impact.BaseMetricV3.CVSSV3.BaseScore,
							Severity:        data.Impact.BaseMetricV3.CVSSV3.BaseSeverity,
							CVSSVector:      data.Impact.BaseMetricV3.CVSSV3.VectorString,
							Impact:          impactString,
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
			f.SetCellValue(sheet, "D"+strconv.Itoa(k+2), v.BaseScore)
			f.SetCellValue(sheet, "E"+strconv.Itoa(k+2), v.Severity)
			f.SetCellValue(sheet, "F"+strconv.Itoa(k+2), v.CVSSVector)
			f.SetCellValue(sheet, "G"+strconv.Itoa(k+2), v.Impact)
			f.SetCellValue(sheet, "H"+strconv.Itoa(k+2), v.Description)
		}
	}

	// Save spreadsheet by the given path.
	xlsxFileName := fmt.Sprintf("%s_%s_%s.xlsx", vendor, component, arch)
	if err := f.SaveAs(xlsxFileName); err != nil {
		fmt.Println(err)
	}
	return nil
}
