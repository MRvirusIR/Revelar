package utils

import (
    "log"
    "os"
)

var Logger *log.Logger

func InitLogger() {
    file, err := os.OpenFile("cdn-finder.log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
    if err != nil {
        log.Fatal("Error opening log file:", err)
    }
    Logger = log.New(file, "CDN-FINDER: ", log.Ldate|log.Ltime|log.Lshortfile)
}
