// Copyright (c) 2017 Tigera, Inc. All rights reserved.

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

	"path/filepath"

	"github.com/projectcalico/calico-upgrade/pkg/constants"
	"github.com/projectcalico/libcalico-go/lib/upgrade/migrator"
	"github.com/projectcalico/yaml"
)

func ensureDirectory(output string) {
	// Make sure the output directory is created.
	ch := &cliHelper{}
	ch.Msg("Preparing reports directory")
	ch.Bullet("creating report directory if it does not exist")
	err := os.MkdirAll(output, os.ModePerm)
	if err != nil {
		ch.Bullet(fmt.Sprintf("unable to create output directory for report: %s", output))
		outputCheckPermsAndExit(output)
	}

	// Make sure we are able to write to each of the files that we need to write to
	// (and delete any current entries).
	ch.Bullet("validating permissions and removing old reports")
	for _, f := range constants.AllReportFiles {
		fp := filepath.Join(output, f)
		file, err := os.OpenFile(fp, os.O_RDWR|os.O_CREATE, os.ModePerm)
		if err != nil {
			ch.Bullet(fmt.Sprintf("unable to open report file for writing: %s", fp))
			outputCheckPermsAndExit(output)
		}
		file.Close()
		err = os.Remove(fp)
		if err != nil {
			ch.Bullet(fmt.Sprintf("unable to delete report file: %s", fp))
			outputCheckPermsAndExit(output)
		}
	}
}

// outputCheckPermsAndExit displays a generic message for the user to check the
// file permissions on the reports directory.
func outputCheckPermsAndExit(output string) {
	ch := &cliHelper{}
	ch.Separator()
	ch.Error("Unable to prepare the reports directory for writing the migration reports. " +
		"Please ensure your file permissions allow the following:")
	ch.Bullet(fmt.Sprintf("creation of the output directory if it doesn't already exist "+
		"(output directory is %s)", output))
	ch.Bullet("creation and deletion of files in the output directory.")
	ch.Msg("If required, use the --output-dir option to specify a different output directory.")
	ch.NewLine()
	os.Exit(1)
}

// printAndOutputReport writes out a set of report files and outputs the
// files to screen.
func printAndOutputReport(output string, data *migrator.MigrationData) {
	fmt.Println("Reports:")
	if len(data.NameConversions) != 0 {
		fp := filepath.Join(output, constants.FileConvertedNames)
		fmt.Printf("- name conversion: %s\n", fp)

		file, err := os.Create(fp)
		if err != nil {
			fmt.Printf("Unable to open report file for writing: %s\n", fp)
		} else {
			for _, n := range data.NameConversions {
				fmt.Fprintf(file, "%s -> %s\n", n.KeyV1.String(), n.KeyV3.String())
			}
		}
		file.Sync()
		file.Close()
	}

	if len(data.NameClashes) != 0 {
		fp := filepath.Join(output, constants.FileNameClashes)
		fmt.Printf("- (errors) name clashes: %s\n", fp)

		file, err := os.Create(fp)
		if err != nil {
			fmt.Printf("Unable to open report file for writing: %s\n", fp)
		} else {
			for _, n := range data.NameClashes {
				fmt.Fprintf(file, "%s and %s -> %s\n", n.KeyV1, n.OtherKeyV1, n.KeyV3)
			}
		}
		file.Sync()
		file.Close()
	}

	if len(data.ConversionErrors) != 0 {
		fp := filepath.Join(output, constants.FileConversionErrors)
		fmt.Printf("- (errors) conversion errors: %s\n", fp)

		file, err := os.Create(fp)
		if err != nil {
			fmt.Printf("Unable to open report file for writing: %s\n", fp)
		} else {
			for _, c := range data.ConversionErrors {
				fmt.Fprintf(file, "%s: %v\n", c.KeyV1, c.Cause)
			}
		}
		file.Sync()
		file.Close()
	}

	if len(data.ConvertedResourceValidationErrors) != 0 {
		fp := filepath.Join(output, constants.FileValidationErrors)
		fmt.Printf("- (errors) v3 validation errors: %s\n", fp)

		file, err := os.Create(fp)
		if err != nil {
			fmt.Printf("Unable to open report file for writing: %s\n", fp)
		} else {
			for _, c := range data.ConvertedResourceValidationErrors {
				fmt.Fprintf(file, "v1 name: %s", c.KeyV1)
				fmt.Fprintf(file, "v3 name: %s", c.KeyV3)
				fmt.Fprintf(file, "error: %s", c.Cause)
				if v3yaml, err := yaml.Marshal(c.ValueV3); err == nil {
					fmt.Fprintf(file, "v3 resource:\n%s", v3yaml)
				}
				fmt.Fprintf(file, "\n\n---\n\n")
			}
		}
		file.Sync()
		file.Close()
	}
}
