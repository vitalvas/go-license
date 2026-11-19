package printer

import (
	"encoding/json"
	"fmt"
	"io"
	"time"

	"go.vitalvas.com/go-license/license"
)

const timeFormat = "2006-01-02 15:04:05 Z07:00"

// Run decodes the license at filePath and writes a human-readable summary to w.
func Run(w io.Writer, filePath string) error {
	lic, err := license.DecodeFile(filePath)
	if err != nil {
		return err
	}

	if lic.ID != "" {
		fmt.Fprintln(w, "License ID:", lic.ID)
	}

	if lic.Customer != "" {
		fmt.Fprintln(w, "License Customer:", lic.Customer)
	}

	if lic.Subscription != "" {
		fmt.Fprintln(w, "License Subscription:", lic.Subscription)
	}

	if lic.Type != "" {
		fmt.Fprintln(w, "License Type:", lic.Type)
	}

	if lic.IssuedAt > 0 {
		unixTimeUTC := time.Unix(lic.IssuedAt, 0)
		fmt.Fprintf(w, "License Issued At: %d (%s) \n", lic.IssuedAt, unixTimeUTC.Format(timeFormat))
	}

	if lic.ExpiredAt > 0 {
		unixTimeUTC := time.Unix(lic.ExpiredAt, 0)
		fmt.Fprintf(w, "License Expires At: %d (%s) \n", lic.ExpiredAt, unixTimeUTC.Format(timeFormat))
	}

	if lic.Data != nil {
		var data map[string]any

		if err := json.Unmarshal(lic.Data, &data); err != nil {
			return err
		}

		payload, err := json.MarshalIndent(data, "", "  ")
		if err != nil {
			return err
		}

		fmt.Fprintln(w, "License Data:")
		fmt.Fprintln(w, string(payload))
	}

	return nil
}
