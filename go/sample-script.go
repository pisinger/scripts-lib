package main

import (
    "encoding/json"
    "fmt"
    "io/ioutil"
    "net/http"
)

func main() {
    url := "https://api.contoso.com/data"

    // Send a GET request to the web server
    response, err := http.Get(url)
    if err != nil {
        fmt.Println("Failed to retrieve data:", err)
        return
    }
    defer response.Body.Close()

    // Read the response body
    body, err := ioutil.ReadAll(response.Body)
    if err != nil {
        fmt.Println("Failed to read response body:", err)
        return
    }

    // Parse the JSON response
    var jsonData map[string]interface{}
    err = json.Unmarshal(body, &jsonData)
    if err != nil {
        fmt.Println("Failed to parse JSON:", err)
        return
    }

    // Print the JSON data
    fmt.Println(jsonData)
}
