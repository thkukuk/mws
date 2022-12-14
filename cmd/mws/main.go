// Copyright 2022 Thorsten Kukuk
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"fmt"
        "io/ioutil"
        "log"
	"os"

	"gopkg.in/yaml.v3"

	"github.com/spf13/cobra"
	"github.com/thkukuk/mws/pkg/mws"
)

var (
	configFile string
)

type Redirects struct {
	UrlPath string `yaml:"urlpath"`
	Target  string `yaml:"target"`
}

type Config struct {
	HttpDir       string `yaml:"httpdir,omitempty"`
        ListenAddr    string `yaml:"listenaddr,omitempty"`
        ListenAddrSSL string `yaml:"listenaddrssl,omitempty"`
	ReadTimeout   int `yaml:"readtimeout,omitempty"`
	WriteTimeout  int `yaml:"writetimeout,omitempty"`
        TlsKey        string `yaml:"tlskey"`
        TlsCert       string `yaml:"tlscert"`
	RevProxy      []Redirects `yaml:"revproxy,omitempty"`
	Quiet         bool `yaml:"quiet,omitempty"`
}

func read_yaml_config(conffile string) (Config, error) {

        var config Config

        file, err := ioutil.ReadFile(conffile)
        if err != nil {
                return config, fmt.Errorf("Cannot read %q: %v", conffile, err)
        }
        err = yaml.Unmarshal(file, &config)
        if err != nil {
                return config, fmt.Errorf("Unmarshal error: %v", err)
        }

        return config, nil
}


func main() {
// mwsCmd represents the mws command
	mwsCmd := &cobra.Command{
		Use:   "mws",
		Short: "Starts a Mini WebServer",
		Long: `Starts a Mini WebServer.
The webserver serves static web pages via http and/or https.
If no certificates are specified, temporary ones will be created on the fly for the local hostname and localhost.

The server listens by default only on port 80. If only https should be provided,
this can be disabled with the '--http=""' option.
`,
		Run: runMwsCmd,
		Args:  cobra.ExactArgs(0),
	}

        mwsCmd.Version = mws.Version

	mwsCmd.Flags().StringVarP(&configFile, "config", "c", configFile, "configuration file")
	mwsCmd.Flags().StringVarP(&mws.HttpDir, "dir", "d", mws.HttpDir, "directory to read files from")
	mwsCmd.Flags().StringVarP(&mws.ListenAddr, "http", "", mws.ListenAddr, "address to listen on for http")
	mwsCmd.Flags().StringVarP(&mws.ListenAddrSSL, "https", "", mws.ListenAddrSSL, "address to listen on for https")
	mwsCmd.Flags().StringVarP(&mws.TlsKey, "tls-key", "", mws.TlsKey, "path to the key file for https")
	mwsCmd.Flags().StringVarP(&mws.TlsCert, "tls-cert", "", mws.TlsCert, "path to the certificate file for https")

	mwsCmd.Flags().BoolVarP(&mws.Quiet, "quiet", "q", mws.Quiet, "don't print connection messages")

	mwsCmd.Flags().IntVarP(&mws.ReadTimeout, "timeout-read", "", mws.ReadTimeout, "timeout in seconds for http read")
	mwsCmd.Flags().IntVarP(&mws.WriteTimeout, "timeout-write", "", mws.WriteTimeout, "timeout in seconds for http write")

	if err := mwsCmd.Execute(); err != nil {
                os.Exit(1)
        }
}

func runMwsCmd(cmd *cobra.Command, args []string) {

	log.Printf("Read yaml config %q\n", configFile)
        if len(configFile) > 0 {
                config, err := read_yaml_config(configFile)
                if err != nil {
                        log.Fatal(err)
                }

                if len(config.HttpDir) > 0 {
                        mws.HttpDir = config.HttpDir
                }
                if len(config.ListenAddr) > 0 {
                        mws.ListenAddr = config.ListenAddr
                }
                if len(config.ListenAddrSSL) > 0 {
                        mws.ListenAddrSSL = config.ListenAddrSSL
                }
                if config.ReadTimeout != 0 {
                        mws.ReadTimeout = config.ReadTimeout
                }
                if config.WriteTimeout != 0 {
                        mws.WriteTimeout = config.WriteTimeout
                }
                if len(config.TlsKey) > 0 {
                        mws.TlsKey = config.TlsKey
                }
                if len(config.TlsCert) > 0 {
                        mws.TlsCert = config.TlsCert
                }
                if len(config.RevProxy) > 0 {
                        mws.RevProxy = make([]mws.Redirects, 0, len(config.RevProxy))
                        for i := range config.RevProxy {
				mws.RevProxy = append(mws.RevProxy, mws.Redirects {
					UrlPath: config.RevProxy[i].UrlPath,
					Target: config.RevProxy[i].Target,})
                        }
                }
		if config.Quiet != false {
			mws.Quiet = config.Quiet
		}
        }

	mws.RunServer()
}
