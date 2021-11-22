package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var configFile string

var rootCmd = &cobra.Command{
	Use:   "AWS-audit",
	Short: "AWS-audit is a AWS service audit",
	Long:  `AWS-audit is a AWS service audit`,
}

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print the version number",
	Long:  `Print the version number`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("AWS-audit v0.1 -- HEAD")
	},
}

var sourceFile = &cobra.Command{
	Use:   "config",
	Short: "Import file configuration (yaml)",
	Long:  `Import file configuration containings services to audit`,
	Run: func(cmd *cobra.Command, args []string) {

	},
}

func init() {
	rootCmd.CompletionOptions.DisableDefaultCmd = true
	rootCmd.AddCommand(versionCmd)
	rootCmd.AddCommand(sourceFile)

	sourceFile.Flags().StringVarP(&configFile, "config", "c", "", "config file aws-audit.yaml")
	sourceFile.MarkFlagRequired("config")
}

func Execute() {

	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
