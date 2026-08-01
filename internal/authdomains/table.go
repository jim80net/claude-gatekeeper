package authdomains

import (
	"fmt"
	"io"
	"text/tabwriter"
)

func WriteTable(w io.Writer, report Report) error {
	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	if _, err := fmt.Fprintln(tw, "MODE\tENFORCING\tCONFORMANT\tSIMULATED DECISION\tREASON"); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(tw, "%s\t%t\t%t\t%s\t%s\n", report.Mode, report.Enforcement, report.Conformant, report.Decision.Decision, report.Decision.ReasonCode); err != nil {
		return err
	}
	if _, err := fmt.Fprintln(tw, "\nCOVERAGE\tSTATE\tGAP"); err != nil {
		return err
	}
	for _, seam := range report.Coverage {
		if _, err := fmt.Fprintf(tw, "%s\t%s\t%s\n", seam.ID, seam.State, seam.KnownGap); err != nil {
			return err
		}
	}
	for _, warning := range report.Warnings {
		if _, err := fmt.Fprintf(tw, "warning\t\t%s\n", warning); err != nil {
			return err
		}
	}
	for _, problem := range report.Errors {
		if _, err := fmt.Fprintf(tw, "error\t\t%s\n", problem); err != nil {
			return err
		}
	}
	return tw.Flush()
}
