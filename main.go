package main
import (
  "fmt"
  "time"
  "example.com/app/smb"
)
func main(){
  r := smb.ScanSMB("127.0.0.1", 445, 3*time.Second)
  fmt.Println(r.String())
}
