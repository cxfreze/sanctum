package providers

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"time"

	"zellion-server/internal/store"
)

var fileRefRegex = regexp.MustCompile(`@([a-zA-Z0-9_./\\-]+\.[a-zA-Z0-9]+)`)

// callSanctumLocal provides a deterministic, intelligent zero-key fallback engine so ZEllion Sanctum
// can run real multi-step workspace inspections, MCP handshakes, file reads, commands, and plans
// out of the box even before external API keys are configured in the Magpie console.
func callSanctumLocal(
	ctx context.Context,
	_ store.UpstreamProvider,
	_ string,
	req ChatRequest,
	cb StreamCallbacks,
) (int, int, error) {
	hasTool := func(name string) bool {
		for _, t := range req.Tools {
			if t.Name == name {
				return true
			}
		}
		return false
	}

	findMCPTool := func() string {
		for _, t := range req.Tools {
			if strings.HasPrefix(t.Name, "mcp__") {
				return t.Name
			}
		}
		return ""
	}

	var lastMsg ChatMessage
	var lastUserPrompt string
	toolResultCount := 0
	for _, m := range req.Messages {
		lastMsg = m
		if m.Role == "user" {
			lastUserPrompt = m.Content
		}
		if m.Role == "tool" {
			toolResultCount++
		}
	}

	streamChunked := func(fn func(string), text string, delay time.Duration) error {
		if fn == nil || text == "" {
			return nil
		}
		runes := []rune(text)
		step := 12
		for i := 0; i < len(runes); i += step {
			select {
			case <-ctx.Done():
				return ctx.Err()
			default:
			}
			end := i + step
			if end > len(runes) {
				end = len(runes)
			}
			fn(string(runes[i:end]))
			if delay > 0 {
				time.Sleep(delay)
			}
		}
		return nil
	}

	level := strings.ToUpper(req.ThinkingLevel)
	if level == "" {
		level = "MEDIUM"
	}

	// Step 1: Fresh user turn -> decide if we should invoke workspace tools!
	if lastMsg.Role == "user" && len(req.Tools) > 0 {
		lower := strings.ToLower(lastUserPrompt)

		if level != "OFF" {
			thinkText := fmt.Sprintf(
				"[%s · Sanctum Local Diagnostic Engine] 正在分析用户任务 %q，检查已挂载的本地 Harness 工具 (%d 个工具) 与上下文约束，准备执行工作区探测步骤...",
				level,
				truncateRunes(lastUserPrompt, 64),
				len(req.Tools),
			)
			if err := streamChunked(cb.OnThinkingDelta, thinkText, 8*time.Millisecond); err != nil {
				return 0, 0, err
			}
		}

		// Check if user mentioned a specific @file to read
		if matches := fileRefRegex.FindStringSubmatch(lastUserPrompt); len(matches) >= 2 && hasTool("read_file") {
			targetPath := matches[1]
			args, _ := json.Marshal(map[string]any{"path": targetPath})
			if cb.OnToolCall != nil {
				cb.OnToolCall(ToolCallSpec{
					ID:        fmt.Sprintf("call_read_%d", time.Now().UnixMilli()),
					Name:      "read_file",
					Arguments: string(args),
				})
			}
			if cb.OnUsage != nil {
				cb.OnUsage(420, 96)
			}
			return 420, 96, nil
		}

		// Check if user asked to run a terminal command or git status
		if (strings.Contains(lower, "git") || strings.Contains(lower, "终端") || strings.Contains(lower, "运行") || strings.Contains(lower, "command")) && hasTool("run_command") {
			cmd := "git status"
			if strings.Contains(lower, "node") {
				cmd = "node -v"
			}
			args, _ := json.Marshal(map[string]any{"command": cmd})
			if cb.OnToolCall != nil {
				cb.OnToolCall(ToolCallSpec{
					ID:        fmt.Sprintf("call_cmd_%d", time.Now().UnixMilli()),
					Name:      "run_command",
					Arguments: string(args),
				})
			}
			if cb.OnUsage != nil {
				cb.OnUsage(380, 88)
			}
			return 380, 88, nil
		}

		// Check if user explicitly mentioned #mcp or mcp
		if strings.Contains(lower, "mcp") {
			if mcpTool := findMCPTool(); mcpTool != "" {
				if cb.OnToolCall != nil {
					cb.OnToolCall(ToolCallSpec{
						ID:        fmt.Sprintf("call_mcp_%d", time.Now().UnixMilli()),
						Name:      mcpTool,
						Arguments: `{}`,
					})
				}
				if cb.OnUsage != nil {
					cb.OnUsage(410, 92)
				}
				return 410, 92, nil
			}
		}

		// Check if planning mode (write_artifact available, write_file absent or prompt asks for plan)
		if (strings.Contains(lower, "plan") || strings.Contains(lower, "规划") || !hasTool("write_file")) && hasTool("list_dir") {
			if cb.OnToolCall != nil {
				cb.OnToolCall(ToolCallSpec{
					ID:        fmt.Sprintf("call_ls_%d", time.Now().UnixMilli()),
					Name:      "list_dir",
					Arguments: `{"path":"."}`,
				})
			}
			if cb.OnUsage != nil {
				cb.OnUsage(360, 84)
			}
			return 360, 84, nil
		}

		// Default: inspect workspace directory first via real list_dir tool!
		if hasTool("list_dir") {
			if cb.OnToolCall != nil {
				cb.OnToolCall(ToolCallSpec{
					ID:        fmt.Sprintf("call_ls_%d", time.Now().UnixMilli()),
					Name:      "list_dir",
					Arguments: `{"path":"."}`,
				})
			}
			if cb.OnUsage != nil {
				cb.OnUsage(390, 90)
			}
			return 390, 90, nil
		}
	}

	// Step 2: Tool result arrived -> synthesize grounded response (or write plan artifact if in planning mode & step 1!)
	if lastMsg.Role == "tool" && toolResultCount == 1 && !hasTool("write_file") && hasTool("write_artifact") {
		planMD := fmt.Sprintf("# Implementation Plan\n\n## Goal\n%s\n\n## Workspace Discovery\n```\n%s\n```\n\n## Verification Steps\n1. Inspect affected modules and interfaces\n2. Apply targeted edits under PreToolUse guardrails\n3. Run test suite and review staged diffs in Editor\n",
			lastUserPrompt,
			truncateRunes(lastMsg.Content, 500),
		)
		args, _ := json.Marshal(map[string]any{
			"title":   "implementation_plan.md",
			"kind":    "plan",
			"content": planMD,
		})
		if cb.OnToolCall != nil {
			cb.OnToolCall(ToolCallSpec{
				ID:        fmt.Sprintf("call_art_%d", time.Now().UnixMilli()),
				Name:      "write_artifact",
				Arguments: string(args),
			})
		}
		if cb.OnUsage != nil {
			cb.OnUsage(560, 180)
		}
		return 560, 180, nil
	}

	if level != "OFF" {
		thinkDone := fmt.Sprintf("[%s · 综合归纳] 已完成工作区工具返回结果核验，准备向客户端流式输出响应。", level)
		if err := streamChunked(cb.OnThinkingDelta, thinkDone, 8*time.Millisecond); err != nil {
			return 0, 0, err
		}
	}

	var reply strings.Builder
	reply.WriteString(fmt.Sprintf("已通过 **ZEllion Server** 聚合网关完成指令处理（当前命中内置免密钥诊断引擎 `sanctum-local`；在服务端管理后台启用 DeepSeek / OpenAI / Anthropic / Gemini 渠道并填入 API Key 后，将自动路由至对应真实大模型）。\n\n"))
	if lastMsg.Role == "tool" {
		reply.WriteString("### 本地 Harness 工具执行结果摘要\n```text\n")
		reply.WriteString(truncateRunes(strings.TrimSpace(lastMsg.Content), 900))
		reply.WriteString("\n```\n\n")
	}
	if len(lastMsg.Attachments) > 0 {
		reply.WriteString(fmt.Sprintf("- 已接收多模态附件 **%d** 个。\n", len(lastMsg.Attachments)))
	}
	reply.WriteString("您可以继续 `@文件` 进行代码读写对比、在「自定义扩展」管理真实 MCP / SKILL.md / 插件，或在服务端隐蔽后台动态调整客户端可见模型、上下文窗口与模态开关。")

	if err := streamChunked(cb.OnTextDelta, reply.String(), 6*time.Millisecond); err != nil {
		return 0, 0, err
	}

	pTok := 520 + len(lastUserPrompt)/3
	cTok := 210
	if cb.OnUsage != nil {
		cb.OnUsage(pTok, cTok)
	}
	return pTok, cTok, nil
}

func truncateRunes(s string, max int) string {
	r := []rune(s)
	if len(r) <= max {
		return s
	}
	return string(r[:max]) + "..."
}
