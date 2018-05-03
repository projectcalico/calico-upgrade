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

func InProgress(args []string) {
	doc := constants.DatastoreIntro + `Usage:
  calico-upgrade inprogress
      [--apiconfigv3=<V3_APICONFIG>]
      [--apiconfigv1=<V1_APICONFIG>]

Example:
  calico-upgrade inprogress --apiconfigv3=/path/to/v3/config --apiconfigv1=/path/to/v1/config

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
  0  Datastore migration is in the process of being upgraded to the Calico V3 API.
  1  Datastore is not currently being migrated.
  >1 Error checking if datastore migration is in progress.

Description:
  The inprogress command reports if there is a datastore migration currently
  in progress. This is not the same as the upgrade being started but not being
  completed or aborted, this command reports if the V1 data is currently being
  converted and written to V3 format.

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
	yes, err := m.IsMigrationInProgress()
	if err == nil {
		if yes {
			// Migration is needed
			ch.Msg("Migration is in Progress.")
			ch.NewLine()
			os.Exit(0)
		} else {
			// Migration is not needed.
			ch.Msg("Migration is NOT in Progress.")
			ch.NewLine()
			os.Exit(1)
		}
	} else {
		// There was an error checking the migration status
		ch.Msg("There was an error checking if datastore migration is in progress")
		ch.Bullet(fmt.Sprint("Error: ", err))
		ch.NewLine()
		os.Exit(2)
	}

	return
}
