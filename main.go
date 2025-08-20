package main

import (
    "flag"
    "fmt"
    "os"

    "github.com/MRvirusIR/cdn-finder/internal/scanner"
    "github.com/MRvirusIR/cdn-finder/internal/utils"
)

func main() {
    domain := flag.String("d", "", "Target domain (e.g. example.com)")
    file := flag.String("f", "", "File containing list of domains")
    active := flag.Bool("active", false, "Enable active verification (requires authorization)")
    flag.Parse()

    if *domain == "" && *file == "" {
        fmt.Println("Usage: cdn-finder -d example.com OR -f domains.txt")
        os.Exit(1)
    }

    utils.InitLogger()

    if *domain != "" {
        scanner.ProcessDomain(*domain, *active)
    } else if *file != "" {
        scanner.ProcessFile(*file, *active)
    }
}
