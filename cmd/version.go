/*
Copyright © 2025 xiexianbin.cn
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at
    http://www.apache.org/licenses/LICENSE-2.0
Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package main

import (
	"github.com/spf13/cobra"
	xca "go.xiexianbin.cn/xca"
)

// versionCmd represents the version command
var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Show version information",
	Long:  `Show version information for XCA including build date, git commit, and platform details.`,
	Run: func(cmd *cobra.Command, args []string) {
		v := xca.GetVersion()
		xca.PrintVersion("xca", v, false)
	},
}
