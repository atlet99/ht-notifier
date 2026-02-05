// Copyright (c) 2026 Abdurakhman Rakhmankulov
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

package notif

import (
	"fmt"
	"strings"
	"time"

	"github.com/atlet99/ht-notifier/internal/config"
)

const (
	severityColorCritical = "🔴"
	severityColorHigh     = "🟠"
	severityColorMedium   = "🟡"
	severityColorLow      = "🟢"
	severityColorUnknown  = "⚪"
)

// formatMessageCommon formats a message using the provided configuration and escape function
func formatMessageCommon(
	msg *Message,
	formatConfig *config.MessageFormatConfig,
	escapeMarkdown bool,
	includeSeverity bool,
	showTimestamp bool,
	escapeFunc func(string) string,
) string {
	var builder strings.Builder

	formatMessagePrefix(&builder, formatConfig, escapeMarkdown, escapeFunc)
	formatMessageTitle(&builder, msg, escapeMarkdown, escapeFunc)
	formatMessageBody(&builder, msg, escapeMarkdown, escapeFunc)
	formatMessageSeverity(&builder, msg, formatConfig, includeSeverity)
	formatMessageLink(&builder, msg, escapeMarkdown, escapeFunc)
	formatMessageTimestamp(&builder, showTimestamp)
	formatMessageMetadata(&builder, msg, escapeMarkdown, escapeFunc)
	formatMessageSuffix(&builder, formatConfig, escapeMarkdown, escapeFunc)

	result := builder.String()
	return truncateMessage(result, formatConfig.MaxMessageLength)
}

// formatMessagePrefix adds custom prefix to message
func formatMessagePrefix(
	builder *strings.Builder,
	formatConfig *config.MessageFormatConfig,
	escapeMarkdown bool,
	escapeFunc func(string) string,
) {
	if formatConfig.CustomPrefix == "" {
		return
	}
	if escapeMarkdown {
		builder.WriteString(escapeFunc(formatConfig.CustomPrefix))
	} else {
		builder.WriteString(formatConfig.CustomPrefix)
	}
	builder.WriteString("\n\n")
}

// formatMessageTitle adds title to message
func formatMessageTitle(
	builder *strings.Builder,
	msg *Message,
	escapeMarkdown bool,
	escapeFunc func(string) string,
) {
	if msg.Title == "" {
		return
	}
	if escapeMarkdown {
		builder.WriteString("*")
		builder.WriteString(escapeFunc(msg.Title))
		builder.WriteString("*")
	} else {
		builder.WriteString(msg.Title)
	}
	builder.WriteString("\n\n")
}

// formatMessageBody adds body to message
func formatMessageBody(
	builder *strings.Builder,
	msg *Message,
	escapeMarkdown bool,
	escapeFunc func(string) string,
) {
	if msg.Body == "" {
		return
	}
	if escapeMarkdown {
		builder.WriteString(escapeFunc(msg.Body))
	} else {
		builder.WriteString(msg.Body)
	}
	builder.WriteString("\n\n")
}

// formatMessageSeverity adds severity information to message
func formatMessageSeverity(
	builder *strings.Builder,
	msg *Message,
	formatConfig *config.MessageFormatConfig,
	includeSeverity bool,
) {
	if !includeSeverity || len(msg.SeverityCounts) == 0 {
		return
	}
	builder.WriteString("*Severity Summary:*\n")
	formatSeverityItem(
		builder, msg.SeverityCounts, "Critical",
		formatConfig.SeverityColors.Critical, severityColorCritical)
	formatSeverityItem(
		builder, msg.SeverityCounts, "High",
		formatConfig.SeverityColors.High, severityColorHigh)
	formatSeverityItem(
		builder, msg.SeverityCounts, "Medium",
		formatConfig.SeverityColors.Medium, severityColorMedium)
	formatSeverityItem(
		builder, msg.SeverityCounts, "Low",
		formatConfig.SeverityColors.Low, severityColorLow)
	formatSeverityItem(
		builder, msg.SeverityCounts, "Unknown",
		formatConfig.SeverityColors.Unknown, severityColorUnknown)
	builder.WriteString("\n")
}

// formatSeverityItem formats a single severity item
func formatSeverityItem(
	builder *strings.Builder,
	counts map[string]int,
	severity, configColor, defaultColor string,
) {
	count, ok := counts[severity]
	if !ok || count <= 0 {
		return
	}
	color := configColor
	if color == "" {
		color = defaultColor
	}
	fmt.Fprintf(builder, "%s %s: %d\n", color, severity, count)
}

// formatMessageLink adds link to message
func formatMessageLink(
	builder *strings.Builder,
	msg *Message,
	escapeMarkdown bool,
	escapeFunc func(string) string,
) {
	if msg.Link == "" {
		return
	}
	if escapeMarkdown {
		fmt.Fprintf(builder, "🔗 [Open in Harbor](%s)", escapeFunc(msg.Link))
	} else {
		fmt.Fprintf(builder, "🔗 Open in Harbor: %s", msg.Link)
	}
	builder.WriteString("\n")
}

// formatMessageTimestamp adds timestamp to message
func formatMessageTimestamp(builder *strings.Builder, showTimestamp bool) {
	if !showTimestamp {
		return
	}
	fmt.Fprintf(builder, "\n⏰ *Timestamp:* %s", time.Now().Format(time.RFC3339))
}

// formatMessageMetadata adds metadata to message
func formatMessageMetadata(
	builder *strings.Builder,
	msg *Message,
	escapeMarkdown bool,
	escapeFunc func(string) string,
) {
	if len(msg.Metadata) == 0 {
		return
	}
	builder.WriteString("\n\n*Additional Information:*\n")
	for key, value := range msg.Metadata {
		if escapeMarkdown {
			fmt.Fprintf(builder, "*%s:* %s\n",
				escapeFunc(key),
				escapeFunc(fmt.Sprintf("%v", value)))
		} else {
			fmt.Fprintf(builder, "*%s:* %v\n", key, value)
		}
	}
}

// formatMessageSuffix adds custom suffix to message
func formatMessageSuffix(
	builder *strings.Builder,
	formatConfig *config.MessageFormatConfig,
	escapeMarkdown bool,
	escapeFunc func(string) string,
) {
	if formatConfig.CustomSuffix == "" {
		return
	}
	builder.WriteString("\n\n")
	if escapeMarkdown {
		builder.WriteString(escapeFunc(formatConfig.CustomSuffix))
	} else {
		builder.WriteString(formatConfig.CustomSuffix)
	}
}

// truncateMessage truncates message if it exceeds max length
func truncateMessage(result string, maxLength int) string {
	if maxLength > 0 && len(result) > maxLength {
		return result[:maxLength-3] + "..."
	}
	return result
}
