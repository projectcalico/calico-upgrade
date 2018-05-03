// Copyright (c) 2016 Tigera, Inc. All rights reserved.

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

package commands

import (
	"fmt"
	"os"
	"strings"

	"github.com/docopt/docopt-go"

	"github.com/projectcalico/calico-upgrade/pkg/constants"
	"github.com/projectcalico/libcalico-go/lib/upgrade/migrator"
	"github.com/projectcalico/libcalico-go/lib/upgrade/migrator/clients"
)

func Needed(args []string) {
	doc := constants.DatastoreIntro + `Usage:
  calico-upgrade needed
      [--apiconfigv3=<V3_APICONFIG>]
      [--apiconfigv1=<V1_APICONFIG>]
      [--no-prompts]

Example:
  calico-upgrade needed --apiconfigv3=/path/to/v3/config --apiconfigv1=/path/to/v1/config

Options:
  -h --help                    Show this screen.
  --apiconfigv3=<V3_APICONFIG> Path to the file containing connection
                               configuration in YAML or JSON format for
                               the Calico v3 API.
                               [default: ` + constants.DefaultConfigPathV3 + `]
  --apiconfigv1=<V1_APICONFIG> Path to the file containing connection
                               configuration in YAML or JSON format for
                               the Calico v1 API.
                               [default: ` + constants.DefaultConfigPathV1 + `]

Return code:
  0  Datastore has not been upgraded to the Calico V3 API.
  1  Datastore does not need to be migrated.
  >1 There was a problem checking if migration is needed.

Description:
  Indicates if the version information in the datastore(s) indicates the need to
  upgrade the data in the datastore or if no upgrade is needed (due to being a
  new install or is already in the V3 format).

` + constants.ReportHelp
	parsedArgs, err := docopt.Parse(doc, args, true, "", false, false)
	if err != nil {
		fmt.Printf("Invalid option:\n  calico-upgrade %s\nUse flag '--help' to read about a specific subcommand.\n", strings.Join(args, " "))
		os.Exit(2)
	}
	if len(parsedArgs) == 0 {
		return
	}
	cfv3 := parsedArgs["--apiconfigv3"].(string)
	cfv1 := parsedArgs["--apiconfigv1"].(string)
	ch := &cliHelper{}

	// Obtain the v1 and v3 clients.
	clientv3, clientv1, err := clients.LoadClients(cfv3, cfv1)
	if err != nil {
		ch.Separator()
		ch.Msg("Failed to check if upgrade is needed.")
		ch.Bullet(fmt.Sprintf("Error accessing the Calico API: %v", err))
		ch.NewLine()
		os.Exit(2)
	}

	m := migrator.New(clientv3, clientv1, ch)

	ch.Separator()
	// Check migration needed status.
	yes, err := m.ShouldMigrate()
	if err == nil {
		if yes {
			// Migration is needed
			ch.Msg("Migration of the datastore to the V3 API is needed.")
			ch.NewLine()
			os.Exit(0)
		} else {
			// Migration is not needed.
			ch.Msg("Migration of the datastore is not needed.")
			ch.NewLine()
			os.Exit(1)
		}
	} else {
		// There was an error checking the migration status
		ch.Msg("There was an error checking if datastore migration is needed")
		ch.Bullet(fmt.Sprint("Error: ", err))
		ch.NewLine()
		os.Exit(2)
	}

	return
}
