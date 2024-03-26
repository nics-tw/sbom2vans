package main

import (
    "fmt"
    "os"

    "github.com/spf13/cobra"
)

func main() {
    var name string

    var rootCmd = &cobra.Command{
        Use:   "sbom2vans",
        Short: "A simple CLI tool",
        Run: func(cmd *cobra.Command, args []string) {
            fmt.Printf("Hello, %s!\n", name)
        },
    }

    rootCmd.Flags().StringVarP(&name, "name", "n", "World", "Specify a name")

    if err := rootCmd.Execute(); err != nil {
        fmt.Println(err)
        os.Exit(1)
    }
}
