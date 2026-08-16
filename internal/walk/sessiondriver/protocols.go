package sessiondriver

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
)

func (c *nativeClient) initialize(workspace string) error {
	switch c.harness {
	case "claude":
		return nil
	case "codex":
		if err := c.request("initialize", map[string]any{"clientInfo": map[string]any{"name": "gatekeeper-walk", "version": "1"}}, nil); err != nil {
			return err
		}
		if err := c.send(map[string]any{"method": "initialized", "params": map[string]any{}}); err != nil {
			return err
		}
		var result map[string]any
		if err := c.request("thread/start", map[string]any{"cwd": workspace, "approvalPolicy": "never", "sandbox": "danger-full-access", "ephemeral": true}, &result); err != nil {
			return err
		}
		thread, _ := result["thread"].(map[string]any)
		c.thread, _ = thread["id"].(string)
		if c.thread == "" {
			return errors.New("Codex thread/start response omitted thread.id")
		}
		return nil
	case "grok":
		var initResult map[string]any
		if err := c.request("initialize", map[string]any{
			"protocolVersion":    1,
			"clientCapabilities": map[string]any{"fs": map[string]any{"readTextFile": false, "writeTextFile": false}, "terminal": false},
			"clientInfo":         map[string]any{"name": "gatekeeper-walk", "version": "1"},
		}, &initResult); err != nil {
			return err
		}
		if os.Getenv("XAI_API_KEY") == "" || !authMethodOffered(initResult, "xai.api_key") {
			return errors.New("Grok disposable drive requires XAI_API_KEY and the xai.api_key ACP auth method")
		}
		if err := c.request("authenticate", map[string]any{"methodId": "xai.api_key", "_meta": map[string]any{"headless": true}}, nil); err != nil {
			return err
		}
		var result map[string]any
		if err := c.request("session/new", map[string]any{"cwd": workspace, "mcpServers": []any{}}, &result); err != nil {
			return err
		}
		c.thread, _ = result["sessionId"].(string)
		if c.thread == "" {
			return errors.New("Grok session/new response omitted sessionId")
		}
		return nil
	default:
		return errors.New("unsupported harness")
	}
}

func (c *nativeClient) runArm(command, arm string) error {
	message := prompt(command)
	var events []map[string]any
	switch c.harness {
	case "claude":
		if err := c.send(map[string]any{
			"type": "user",
			"message": map[string]any{
				"role":    "user",
				"content": []any{map[string]any{"type": "text", "text": message}},
			},
			"parent_tool_use_id": nil,
		}); err != nil {
			return err
		}
		for {
			event, err := c.read()
			if err != nil {
				return err
			}
			events = append(events, event)
			if event["type"] == "result" {
				break
			}
		}
	case "codex":
		id := c.nextID
		c.nextID++
		if err := c.send(map[string]any{"id": id, "method": "turn/start", "params": map[string]any{
			"threadId": c.thread, "input": []any{map[string]any{"type": "text", "text": message}}, "approvalPolicy": "never",
		}}); err != nil {
			return err
		}
		for {
			event, err := c.read()
			if err != nil {
				return err
			}
			events = append(events, event)
			if event["method"] == "turn/completed" {
				break
			}
		}
	case "grok":
		id := c.nextID
		c.nextID++
		if err := c.send(c.rpcMessage(id, "session/prompt", map[string]any{
			"sessionId": c.thread, "prompt": []any{map[string]any{"type": "text", "text": message}},
		})); err != nil {
			return err
		}
		for {
			event, err := c.read()
			if err != nil {
				return err
			}
			events = append(events, event)
			if eventID(event) == id {
				break
			}
		}
	}
	if arm == "benign" {
		if !hasExecutionOutput(c.harness, events, "GATEKEEPER_WALK_BENIGN") {
			return errors.New("native event stream did not prove benign command output")
		}
		return nil
	}
	if !eventsContain(events, denyReason) {
		return errors.New("native event stream did not carry the isolated Gatekeeper deny reason")
	}
	return nil
}

func (c *nativeClient) request(method string, params map[string]any, result *map[string]any) error {
	id := c.nextID
	c.nextID++
	if err := c.send(c.rpcMessage(id, method, params)); err != nil {
		return err
	}
	for {
		event, err := c.read()
		if err != nil {
			return err
		}
		if eventID(event) != id {
			continue
		}
		if rpcError := event["error"]; rpcError != nil {
			return fmt.Errorf("%s: %v", method, rpcError)
		}
		if result != nil {
			value, ok := event["result"].(map[string]any)
			if !ok {
				return fmt.Errorf("%s response omitted object result", method)
			}
			*result = value
		}
		return nil
	}
}

func (c *nativeClient) rpcMessage(id int, method string, params map[string]any) map[string]any {
	message := map[string]any{"id": id, "method": method, "params": params}
	if c.harness == "grok" {
		message["jsonrpc"] = "2.0"
	}
	return message
}

func authMethodOffered(result map[string]any, wanted string) bool {
	methods, _ := result["authMethods"].([]any)
	for _, method := range methods {
		value, _ := method.(map[string]any)
		if value["id"] == wanted {
			return true
		}
	}
	return false
}

func (c *nativeClient) send(value any) error {
	data, err := json.Marshal(value)
	if err != nil {
		return err
	}
	data = append(data, '\n')
	_, err = c.stdin.Write(data)
	return err
}

func (c *nativeClient) read() (map[string]any, error) {
	line, err := c.events.ReadBytes('\n')
	if err != nil {
		if err == io.EOF && len(bytes.TrimSpace(line)) != 0 {
			// Decode the final unterminated object before reporting EOF.
		} else {
			return nil, err
		}
	}
	var event map[string]any
	if decodeErr := json.Unmarshal(bytes.TrimSpace(line), &event); decodeErr != nil {
		return nil, fmt.Errorf("decode %s event: %w", c.harness, decodeErr)
	}
	return event, nil
}

func eventID(event map[string]any) int {
	switch value := event["id"].(type) {
	case float64:
		return int(value)
	case int:
		return value
	case json.Number:
		parsed, _ := value.Int64()
		return int(parsed)
	default:
		return 0
	}
}

func eventsContain(events []map[string]any, needle string) bool {
	for _, event := range events {
		data, _ := json.Marshal(event)
		if strings.Contains(string(data), needle) {
			return true
		}
	}
	return false
}

func hasExecutionOutput(harness string, events []map[string]any, marker string) bool {
	for _, event := range events {
		data, _ := json.Marshal(event)
		text := string(data)
		if !strings.Contains(text, marker) {
			continue
		}
		switch harness {
		case "claude":
			if strings.Contains(text, `"tool_result"`) {
				return true
			}
		case "codex":
			method, _ := event["method"].(string)
			if strings.Contains(method, "commandExecution") {
				return true
			}
		case "grok":
			method, _ := event["method"].(string)
			if method == "session/update" && (strings.Contains(text, `"tool_call_update"`) || strings.Contains(text, `"toolCallId"`)) {
				return true
			}
		}
	}
	return false
}
