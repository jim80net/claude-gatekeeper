package authdomains

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
)

func loadStrict(path string, target any) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	dec := json.NewDecoder(f)
	dec.DisallowUnknownFields()
	if err := dec.Decode(target); err != nil {
		return err
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		if err == nil {
			return fmt.Errorf("multiple JSON values")
		}
		return err
	}
	return nil
}

func LoadPolicy(path string) (PolicyGeneration, error) {
	var v PolicyGeneration
	return v, loadStrict(path, &v)
}
func LoadRequest(path string) (Request, error) { var v Request; return v, loadStrict(path, &v) }
func LoadCoverage(path string) (CoverageManifest, error) {
	var v CoverageManifest
	return v, loadStrict(path, &v)
}

func WriteJSON(w io.Writer, report Report) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(report)
}
