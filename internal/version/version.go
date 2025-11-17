// Copyright (c) 2025 Abdurakhman Rakhmankulov
//
// Licensed under the MIT License (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://opensource.org/licenses/MIT
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package version provides version information for the application.
package version

// These variables are injected via -ldflags during build.
var (
	Version = "dev"     // e.g. 0.1.0
	Commit  = "none"    // short git sha
	Date    = "unknown" // build timestamp in UTC, RFC3339
)

// String returns the version string
func String() string {
	return Version
}
