package main

import (
	"bytes"
	"crypto/tls"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"strings"
	"text/template"
	"time"
)

// DRAC contains all of the information required
// to connect to a Dell DRAC KVM
type DRAC struct {
	Host       string
	Username   string
	Password   string
	Version    int
	SessionKey string
}

// Templates is a map of each viewer.jnlp template for
// the various Dell iDRAC versions, keyed by version number
var Templates = map[int]string{
	1: ikvm169,
	2: ilo2,
	6: viewer6,
	7: viewer7,
}

// initialize HTTPClient
var (
        httpClient *http.Client
)
func init() {
        httpClient = createHTTPClient()
}

// there must be a better way to store this for re-use
// look at setting the cookie properly?
var SID = ""
var sessionkey = ""

// createHTTPClient for connection re-use
func createHTTPClient() *http.Client {
        transport := &http.Transport{
                TLSClientConfig: &tls.Config{
                        InsecureSkipVerify: true,
                },
                Dial: func(netw, addr string) (net.Conn, error) {
                        deadline := time.Now().Add(5 * time.Second)
                        c, err := net.DialTimeout(netw, addr, time.Second*5)
                        if err != nil {
                                return nil, err
                        }
                        c.SetDeadline(deadline)
                        return c, nil
                },
        }

        client := &http.Client{
                Transport: transport,
        }

        return client
}


func debug(data []byte, err error) {
	if err == nil {
		fmt.Printf("%s\n\n", data)
	} else {
		log.Fatalf("%s\n\n", err)
	}
}

// GetVersion attempts to detect the iDRAC version by checking
// if various known libraries are available via HTTP GET requests.
// Retursn the version if found, or -1 if unknown
func (d *DRAC) GetVersion() int {

	log.Print("Detecting version...")

	version := -1

	// Check for iDRAC7 specific libs
	if response, err := httpClient.Head("https://" + d.Host + "/software/avctKVMIOMac64.jar"); err == nil {
		defer response.Body.Close()
		if response.StatusCode == 200 {
			return 7
		}
	}

	// Check for iDRAC6 specific libs
	if response, err := httpClient.Head("https://" + d.Host + "/software/jpcsc.jar"); err == nil {
		defer response.Body.Close()
		if response.StatusCode == 200 {
			return 6
		}
	}

	// Check for iLO specific file
	var json_string = []byte("{\"method\":\"login\",\"user_login\":\""+d.Username+"\",\"password\":\""+d.Password+"\"}")
	if response, err := httpClient.Post("https://" + d.Host + "/json/login_session", "application/json", bytes.NewBuffer(json_string)); err == nil {
		defer response.Body.Close()
		if response.StatusCode == 200 {
			for _, c := range response.Cookies() {
				log.Printf(c.Name + " = " + c.Value)
				if "sessionKey" == c.Name && c.Value != "" {
					d.SessionKey = c.Value
				}
			}
			return 2
		}
	}

	// SuperMicro login, if we can post to the path, its probably supermicro
	// further we will then use the Cookie SID for the jnlp file
	data := fmt.Sprintf("name=%s&pwd=%s", d.Username, d.Password)
	if response, err := httpClient.Post("https://"+d.Host+"/cgi/login.cgi", "text/plain", strings.NewReader(data)); err == nil {
		defer response.Body.Close()
		if response.StatusCode == 200 {
			for _, c := range response.Cookies() {
				if "SID" == c.Name && c.Value != "" {
					SID = "SID="+c.Value
					log.Printf("Setting username/password to cookie SID")
					d.Username = c.Value
					d.Password = c.Value
				}
			}
			return 1
		}
	}


	return version

}

// For SuperMicro download the jnlp file using the session id and return its content
func (d *DRAC) get_jnlp() (string, error){
	url := "https://"+d.Host+"/cgi/url_redirect.cgi?url_name=ikvm&url_type=jwsk"
	request, err := http.NewRequest("GET", url, nil)
	if err == nil {
		request.Header.Add("Cookie", SID)
		// Seems to avoid 500 errors on some SuperMicro interfaces
		request.Header.Add("Referer", "127.0.0.1")
	}
	if response, err := httpClient.Do(request); err == nil {
		defer response.Body.Close()
		if response.StatusCode == 200 {
			if buff, err2 := ioutil.ReadAll(response.Body); err2 == nil {
				bodyString := string(buff)
				return bodyString, err2
			} else {
				return "", err2
			}
		}
	}
	return "", err
}

// Viewer returns a viewer.jnlp template filled out with the
// necessary details to connect to a particular DRAC host
func (d *DRAC) Viewer() (string, error) {

	var version int

	// Check we have a valid DRAC viewer template for this DRAC version
	if d.Version < 0 {
		version = d.GetVersion()
	} else {
		version = d.Version
	}
	if version < 0 {
		return "", errors.New("unable to detect DRAC version")
	}

	if version == 6 || version == 7 {
		log.Printf("Found iDRAC version %d", version)

		if _, ok := Templates[version]; !ok {
			msg := fmt.Sprintf("no support for DRAC v%d", version)
			return "", errors.New(msg)
		}

		// Generate a JNLP viewer from the template
		// Injecting the host/user/pass information
		buff := bytes.NewBufferString("")
		err := template.Must(template.New("viewer").Parse(Templates[version])).Execute(buff, d)
		return buff.String(), err
	} else if version == 2 {
		log.Printf("Found iLO")

		// Generate a JNLP viewer from the template
		// Injecting the host/user/pass information
		buff := bytes.NewBufferString("")
		err := template.Must(template.New("viewer").Parse(Templates[version])).Execute(buff, d)
		return buff.String(), err
	} else {
		log.Printf("Found other version %d", version)

		// Download JNLP file and return the content
		jnlp_data, err := d.get_jnlp()
		return jnlp_data, err
	}
}
