#!/bin/bash

# Add or update copyright header in Go files
set -euo pipefail
COPYRIGHT="Copyright (c) $(date +%Y) Abdurakhman Rakhmankulov"

# Go file copyright header (using // comments)
GO_HEADER="// $COPYRIGHT
//
// Licensed under the MIT License (the \"License\");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://opensource.org/licenses/MIT
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an \"AS IS\" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License."

# Find all Go files
find . -name "*.go" -not -path "./vendor/*" -not -path "./.git/*" -not -path "./hack/*" -not -path "./test_results/*" -not -path "./docs/*" -not -path "./bin/*" -not -path "./dist/*" | while read -r file; do
    # Check if file already has any copyright header
    if head -n 20 "$file" | grep -i -q "Copyright" 2>/dev/null; then
        echo "✓ $file (already has copyright)"
        continue
    fi
    
    # Check if file has package declaration
    if ! grep -q "^package " "$file" 2>/dev/null; then
        echo "⊘ Skipping $file (no package declaration)"
        continue
    fi
    
    # Add copyright before package declaration
    tmpfile=$(mktemp)
    echo "$GO_HEADER" > "$tmpfile"
    echo "" >> "$tmpfile"
    cat "$file" >> "$tmpfile"
    mv "$tmpfile" "$file"
    echo "✓ Added copyright to $file"
done

echo ""
echo "Copyright headers check completed"

