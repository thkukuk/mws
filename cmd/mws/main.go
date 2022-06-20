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
	"os"
	"github.com/spf13/cobra"
	"github.com/thkukuk/mws/pkg/mws"
)

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

	mwsCmd.Flags().StringVarP(&mws.HttpDir, "dir", "d", mws.HttpDir, "directory to read files from")
	mwsCmd.Flags().StringVarP(&mws.ListenAddr, "http", "", mws.ListenAddr, "address to listen on for http")
	mwsCmd.Flags().StringVarP(&mws.ListenAddrSSL, "https", "", mws.ListenAddrSSL, "address to listen on for https")
	mwsCmd.Flags().StringVarP(&mws.TlsKey, "tls-key", "", mws.TlsKey, "path to the key file for https")
	mwsCmd.Flags().StringVarP(&mws.TlsCert, "tls-cert", "", mws.TlsCert, "path to the certificate file for https")

	mwsCmd.Flags().IntVarP(&mws.ReadTimeout, "timeout-read", "", mws.ReadTimeout, "timeout in seconds for http read")
	mwsCmd.Flags().IntVarP(&mws.WriteTimeout, "timeout-write", "", mws.WriteTimeout, "timeout in seconds for http write")

	if err := mwsCmd.Execute(); err != nil {
                os.Exit(1)
        }
}

func runMwsCmd(cmd *cobra.Command, args []string) {
	mws.RunServer()
}
