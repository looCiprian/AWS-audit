package cmd

import (
	"AWS-audit/internal/auditor"
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var configFile string

var rootCmd = &cobra.Command{
	Use:   "AWS-audit",
	Short: "AWS-audit is a AWS service audit",
	Long:  `AWS-audit is a AWS service audit`,
	Run: func(cmd *cobra.Command, args []string) {
		servicesToAudit := auditor.AuditorImporter(configFile)
		auditor.Run(servicesToAudit)
	},
}

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print the version number",
	Long:  `Print the version number`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("AWS-audit v0.1 -- HEAD")
	},
}

func init() {
	rootCmd.CompletionOptions.DisableDefaultCmd = true
	rootCmd.AddCommand(versionCmd)

	rootCmd.Flags().StringVarP(&configFile, "config", "c", "", "config file aws-audit.yaml")
	rootCmd.MarkFlagRequired("config")
}

func Execute() {

	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
