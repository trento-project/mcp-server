package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"reflect"
	"strings"
	"time"

	"github.com/ag-ui-protocol/ag-ui/sdks/community/go/pkg/core/events"
	"github.com/tmc/langchaingo/llms"
	"github.com/tmc/langchaingo/schema"
	"github.com/trento-project/mcp-server/internal/telemetry"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
)

// CallbacksHandler turns langchaingo callbacks into AG-UI protocol events.
type CallbacksHandler struct {
	returnChan      chan<- json.RawMessage
	threadID        string
	runID           string
	messageID       string
	messageStarted  bool
	toolCallID      string
	toolName        string
	stepID          string
	runFinished     bool
	metrics         *telemetry.Metrics
	tracer          trace.Tracer
	llmStart        time.Time
	llmSpan         trace.Span
	llmModel        string
	llmToolSchemas  []string
	toolResults     []toolResult
	llmPrompts      []string
	llmOutput       string
	llmSystemPrompt string
}

type toolResult struct {
	callID  string
	name    string
	content string
}

// NewCallbacksHandler creates a callbacks handler that forwards AG-UI events into the provided channel.
func NewCallbacksHandler(ch chan<- json.RawMessage, threadID, runID, messageID string, metrics *telemetry.Metrics, tracer trace.Tracer, llmModel string, llmToolSchemas []string) *CallbacksHandler {
	if threadID == "" {
		threadID = events.GenerateThreadID()
	}
	if runID == "" {
		runID = events.GenerateRunID()
	}
	if messageID == "" {
		messageID = events.GenerateMessageID()
	}
	return &CallbacksHandler{
		returnChan:     ch,
		threadID:       threadID,
		runID:          runID,
		messageID:      messageID,
		metrics:        metrics,
		tracer:         tracer,
		llmModel:       llmModel,
		llmToolSchemas: llmToolSchemas,
	}
}

const (
	openInferenceSpanKindKey = "openinference.span.kind"
	llmSystemKey             = "llm.system"
	llmProviderKey           = "llm.provider"
	llmModelNameKey          = "llm.model_name"
	llmInputMessagesKey      = "llm.input_messages"
	llmOutputMessagesKey     = "llm.output_messages"
	llmPromptTokensKey       = "llm.token_count.prompt"
	llmCompletionTokensKey   = "llm.token_count.completion"
	llmTotalTokensKey        = "llm.token_count.total"
	inputValueKey            = "input.value"
	inputMimeTypeKey         = "input.mime_type"
	outputValueKey           = "output.value"
	outputMimeTypeKey        = "output.mime_type"
)

func truncateTraceValue(value string, max int) string {
	if len(value) <= max {
		return value
	}
	return value[:max] + "..."
}

func estimateTokenCount(text string) int64 {
	trimmed := strings.TrimSpace(text)
	if trimmed == "" {
		return 0
	}
	// Rough approximation: ~4 characters per token.
	count := (len(trimmed) + 3) / 4
	return int64(count)
}

func buildMessageJSON(role string, contents []string) string {
	type msg struct {
		Role    string `json:"role"`
		Content string `json:"content"`
	}
	if len(contents) == 0 {
		return ""
	}
	messages := make([]msg, 0, len(contents))
	for _, content := range contents {
		messages = append(messages, msg{Role: role, Content: content})
	}
	b, err := json.Marshal(messages)
	if err != nil {
		return ""
	}
	return string(b)
}

func inferLLMSystemProvider(model string) (string, string) {
	if strings.Contains(strings.ToLower(model), "gemini") {
		return "google_ai_studio", "google"
	}
	return "unknown", "unknown"
}

func setMessageAttributes(span trace.Span, prefix string, startIndex int, role string, contents []string) int {
	index := startIndex
	for _, content := range contents {
		span.SetAttributes(
			attribute.String(fmt.Sprintf("%s.%d.message.role", prefix, index), role),
			attribute.String(fmt.Sprintf("%s.%d.message.content", prefix, index), truncateTraceValue(content, maxSpanAttrLen)),
		)
		index++
	}
	return index
}

func setToolMessageAttributes(span trace.Span, prefix string, startIndex int, tool toolResult) int {
	span.SetAttributes(
		attribute.String(fmt.Sprintf("%s.%d.message.role", prefix, startIndex), "tool"),
		attribute.String(fmt.Sprintf("%s.%d.message.content", prefix, startIndex), truncateTraceValue(tool.content, maxSpanAttrLen)),
	)
	if tool.callID != "" {
		span.SetAttributes(
			attribute.String(fmt.Sprintf("%s.%d.message.tool_call_id", prefix, startIndex), tool.callID),
		)
	}
	if tool.name != "" {
		span.SetAttributes(
			attribute.String(fmt.Sprintf("%s.%d.message.name", prefix, startIndex), tool.name),
		)
	}
	return startIndex + 1
}

func setToolSchemas(span trace.Span, schemas []string) {
	for i, schema := range schemas {
		if schema == "" {
			continue
		}
		span.SetAttributes(
			attribute.String(fmt.Sprintf("llm.tools.%d.tool.json_schema", i), truncateTraceValue(schema, maxSpanAttrLen)),
		)
	}
}

func buildInputValue(model string, messages []map[string]any) string {
	if len(messages) == 0 {
		return ""
	}
	payload := map[string]any{"messages": messages}
	if model != "" {
		payload["model"] = model
	}
	b, err := json.Marshal(payload)
	if err != nil {
		return ""
	}
	return string(b)
}

func buildOutputValue(messages []map[string]any) string {
	if len(messages) == 0 {
		return ""
	}
	payload := map[string]any{"messages": messages}
	b, err := json.Marshal(payload)
	if err != nil {
		return ""
	}
	return string(b)
}

// send marshals the event using its ToJSON method and pushes it to the channel.
func (h *CallbacksHandler) send(event interface{}) {
	if event == nil {
		return
	}
	// If run is finished, drop any text/tool start events to avoid protocol violations
	if h.runFinished {
		switch ev := event.(type) {
		case interface{ ToJSON() ([]byte, error) }:
			if b, err := ev.ToJSON(); err == nil {
				// quick check for run_finished event
				if bytes.Contains(b, []byte("RUN_FINISHED")) {
					// allow run finished (idempotent)
					break
				}
				// drop other events
				return
			}
		default:
			return
		}
	}
	type jsonable interface{ ToJSON() ([]byte, error) }
	if ev, ok := event.(jsonable); ok {
		if b, err := ev.ToJSON(); err == nil {
			h.sendBytes(b)
		}
	}
}

func (h *CallbacksHandler) sendBytes(b []byte) {
	select {
	case h.returnChan <- json.RawMessage(b):
	default:
		// drop if buffer full to avoid blocking the chain
	}
}

func (h *CallbacksHandler) ensureMessageID() string {
	if h.messageID == "" {
		h.messageID = events.GenerateMessageID()
	}
	return h.messageID
}

func (h *CallbacksHandler) HandleText(ctx context.Context, text string) {
	msgID := h.ensureMessageID()
	if !h.messageStarted {
		h.send(events.NewTextMessageStartEvent(msgID, events.WithRole("assistant")))
		h.messageStarted = true
	}
	h.send(events.NewTextMessageContentEvent(msgID, text))
}

func (h *CallbacksHandler) HandleLLMStart(ctx context.Context, prompts []string) {
	h.llmStart = time.Now()
	h.llmPrompts = append([]string(nil), prompts...)
	h.llmOutput = ""
	if h.tracer != nil {
		attrs := []attribute.KeyValue{
			attribute.String(openInferenceSpanKindKey, "LLM"),
			attribute.Int("llm.prompt_count", len(prompts)),
		}
		if h.llmModel != "" {
			attrs = append(attrs, attribute.String(llmModelNameKey, h.llmModel))
			if system, provider := inferLLMSystemProvider(h.llmModel); system != "" {
				attrs = append(attrs,
					attribute.String(llmSystemKey, system),
					attribute.String(llmProviderKey, provider),
				)
			}
		}
		if len(prompts) > 0 || len(h.toolResults) > 0 || h.llmSystemPrompt != "" {
			messages := make([]map[string]any, 0, len(prompts)+len(h.toolResults)+1)
			if h.llmSystemPrompt != "" {
				messages = append(messages, map[string]any{
					"role":    "system",
					"content": h.llmSystemPrompt,
				})
			}
			for _, prompt := range prompts {
				messages = append(messages, map[string]any{
					"role":    "user",
					"content": prompt,
				})
			}
			for _, tool := range h.toolResults {
				message := map[string]any{
					"role":    "tool",
					"content": tool.content,
				}
				if tool.callID != "" {
					message["tool_call_id"] = tool.callID
				}
				if tool.name != "" {
					message["name"] = tool.name
				}
				messages = append(messages, message)
			}
			if inputValue := buildInputValue(h.llmModel, messages); inputValue != "" {
				attrs = append(attrs, attribute.String(inputValueKey, truncateTraceValue(inputValue, maxSpanAttrLen)))
				attrs = append(attrs, attribute.String(inputMimeTypeKey, "application/json"))
			}
		}
		if h.llmModel != "" {
			invocationParams, err := json.Marshal(map[string]any{"model": h.llmModel})
			if err == nil {
				attrs = append(attrs, attribute.String("llm.invocation_parameters", truncateTraceValue(string(invocationParams), maxSpanAttrLen)))
			}
		}
		_, h.llmSpan = h.tracer.Start(ctx, "llm.call", trace.WithAttributes(attrs...))
	}
	if h.llmSpan != nil && len(prompts) > 0 {
		index := 0
		if h.llmSystemPrompt != "" {
			index = setMessageAttributes(h.llmSpan, llmInputMessagesKey, index, "system", []string{h.llmSystemPrompt})
		}
		index = setMessageAttributes(h.llmSpan, llmInputMessagesKey, index, "user", prompts)
		for _, tool := range h.toolResults {
			index = setToolMessageAttributes(h.llmSpan, llmInputMessagesKey, index, tool)
		}
	}
	if h.llmSpan != nil && len(h.llmToolSchemas) > 0 {
		setToolSchemas(h.llmSpan, h.llmToolSchemas)
	}
	// Generate new message ID for this LLM interaction
	h.messageID = events.GenerateMessageID()
	// RUN_STARTED is sent by ExecuteWithStreaming before callbacks start
	// Begin assistant message
	h.send(events.NewTextMessageStartEvent(h.messageID, events.WithRole("assistant")))
	h.messageStarted = true
}

func (h *CallbacksHandler) HandleLLMGenerateContentStart(ctx context.Context, ms []llms.MessageContent) {
	if h.llmStart.IsZero() {
		h.llmStart = time.Now()
		if h.tracer != nil {
			_, h.llmSpan = h.tracer.Start(ctx, "llm.call")
		}
	}
	msgID := h.ensureMessageID()
	role := "assistant"
	for _, m := range ms {
		if len(m.Parts) > 0 {
			if _, ok := m.Parts[0].(llms.ToolCallResponse); ok {
				role = "tool"
				break
			}
		}
	}
	if !h.messageStarted {
		h.send(events.NewTextMessageStartEvent(msgID, events.WithRole(role)))
		h.messageStarted = true
	}
}

func (h *CallbacksHandler) HandleLLMGenerateContentEnd(ctx context.Context, res *llms.ContentResponse) {
	if h.metrics != nil && !h.llmStart.IsZero() {
		h.metrics.LLMCallLatency.Record(ctx, float64(time.Since(h.llmStart).Milliseconds()))
	}
	outputText := extractOutputText(res)
	if outputText == "" && h.llmOutput != "" {
		outputText = h.llmOutput
	}
	if h.metrics != nil {
		if inputTokens, outputTokens, ok := extractTokenUsage(res); ok {
			if inputTokens > 0 {
				h.metrics.LLMInputTokens.Add(ctx, inputTokens)
			}
			if outputTokens > 0 {
				h.metrics.LLMOutputTokens.Add(ctx, outputTokens)
			}
			if h.llmSpan != nil {
				h.llmSpan.AddEvent("llm.tokens", trace.WithAttributes(
					attribute.Int64("llm.input_tokens", inputTokens),
					attribute.Int64("llm.output_tokens", outputTokens),
				))
				attrs := []attribute.KeyValue{}
				if inputTokens > 0 {
					attrs = append(attrs, attribute.Int64(llmPromptTokensKey, inputTokens))
				}
				if outputTokens > 0 {
					attrs = append(attrs, attribute.Int64(llmCompletionTokensKey, outputTokens))
				}
				if inputTokens > 0 && outputTokens > 0 {
					attrs = append(attrs, attribute.Int64(llmTotalTokensKey, inputTokens+outputTokens))
				}
				if len(attrs) > 0 {
					h.llmSpan.SetAttributes(attrs...)
				}
			}
		} else if len(h.llmPrompts) > 0 || outputText != "" {
			inputTokens := estimateTokenCount(strings.Join(h.llmPrompts, "\n"))
			outputTokens := estimateTokenCount(outputText)
			if inputTokens > 0 {
				h.metrics.LLMInputTokens.Add(ctx, inputTokens)
			}
			if outputTokens > 0 {
				h.metrics.LLMOutputTokens.Add(ctx, outputTokens)
			}
			if h.llmSpan != nil {
				h.llmSpan.AddEvent("llm.tokens.estimated", trace.WithAttributes(
					attribute.Int64("llm.input_tokens", inputTokens),
					attribute.Int64("llm.output_tokens", outputTokens),
				))
				attrs := []attribute.KeyValue{}
				if inputTokens > 0 {
					attrs = append(attrs, attribute.Int64(llmPromptTokensKey, inputTokens))
				}
				if outputTokens > 0 {
					attrs = append(attrs, attribute.Int64(llmCompletionTokensKey, outputTokens))
				}
				if inputTokens > 0 && outputTokens > 0 {
					attrs = append(attrs, attribute.Int64(llmTotalTokensKey, inputTokens+outputTokens))
				}
				if len(attrs) > 0 {
					h.llmSpan.SetAttributes(attrs...)
				}
			}
		}
	}
	if h.llmSpan != nil {
		if outputText != "" {
			// Set flattened message attributes first
			setMessageAttributes(h.llmSpan, llmOutputMessagesKey, 0, "assistant", []string{outputText})

			// Build structured output.value as JSON
			outputValue := buildOutputValue([]map[string]any{{"role": "assistant", "content": outputText}})
			if outputValue != "" {
				h.llmSpan.SetAttributes(
					attribute.String(outputValueKey, truncateTraceValue(outputValue, maxSpanAttrLen)),
					attribute.String(outputMimeTypeKey, "application/json"),
				)
			}
		}
	}
	if h.llmSpan != nil {
		h.llmSpan.End()
		h.llmSpan = nil
	}
	h.llmStart = time.Time{}
	h.llmPrompts = nil
	h.llmOutput = ""
	h.llmSystemPrompt = ""
	if h.messageID != "" {
		h.send(events.NewTextMessageEndEvent(h.messageID))
		h.messageStarted = false
	}
	// Reset message ID for next interaction
	h.messageID = ""
}

func (h *CallbacksHandler) HandleLLMError(ctx context.Context, err error) {
	if h.metrics != nil && !h.llmStart.IsZero() {
		h.metrics.LLMCallLatency.Record(ctx, float64(time.Since(h.llmStart).Milliseconds()))
	}
	if h.llmSpan != nil {
		h.llmSpan.RecordError(err)
		h.llmSpan.SetStatus(codes.Error, err.Error())
		h.llmSpan.End()
		h.llmSpan = nil
	}
	h.llmStart = time.Time{}
	msgID := h.ensureMessageID()
	if !h.messageStarted {
		h.send(events.NewTextMessageStartEvent(msgID, events.WithRole("assistant")))
		h.messageStarted = true
	}
	h.send(events.NewTextMessageContentEvent(msgID, "Error: "+err.Error()))
	h.send(events.NewTextMessageEndEvent(msgID))
	h.messageStarted = false
	// Also emit run error
	h.send(events.NewRunErrorEvent(err.Error(), events.WithRunID(h.runID)))
}

func (h *CallbacksHandler) HandleChainStart(ctx context.Context, inputs map[string]any) {
	h.stepID = events.GenerateStepID()
	h.send(events.NewStepStartedEvent(h.stepID))
}

func (h *CallbacksHandler) HandleChainEnd(ctx context.Context, outputs map[string]any) {
	if h.stepID != "" {
		h.send(events.NewStepFinishedEvent(h.stepID))
		h.stepID = ""
	}
}

func (h *CallbacksHandler) HandleChainError(ctx context.Context, err error) {
	// Log the error but don't send it to users - it's often a parsing error
	// that will be handled gracefully at a higher level (in agent.go)
	slog.WarnContext(ctx, "callbacks: chain error", "error", err)

	if h.stepID != "" {
		h.send(events.NewStepFinishedEvent(h.stepID))
		h.stepID = ""
	}
}

func (h *CallbacksHandler) HandleToolStart(ctx context.Context, input string) {
	// Only generate new tool call ID if one isn't already active (from HandleAgentAction)
	if h.toolCallID == "" {
		h.toolCallID = events.GenerateToolCallID()
		h.toolName = "tool"
		start := events.NewToolCallStartEvent(h.toolCallID, h.toolName)
		if h.messageID != "" {
			start = events.NewToolCallStartEvent(h.toolCallID, h.toolName, events.WithParentMessageID(h.messageID))
		}
		h.send(start)
	}
	// Always send args (whether we just started or reusing existing tool call)
	h.send(events.NewToolCallArgsEvent(h.toolCallID, input))
	slog.DebugContext(ctx, "callbacks: tool start", "toolCallID", h.toolCallID, "toolName", h.toolName, "args_preview", input)
}

func (h *CallbacksHandler) HandleToolEnd(ctx context.Context, output string) {
	if h.toolCallID == "" {
		return
	}
	slog.DebugContext(ctx, "callbacks: tool end", "toolCallID", h.toolCallID, "toolName", h.toolName, "output_preview", output)
	h.send(events.NewToolCallEndEvent(h.toolCallID))
	resultMsgID := events.GenerateMessageID()
	h.send(events.NewToolCallResultEvent(resultMsgID, h.toolCallID, output))
	h.toolResults = append(h.toolResults, toolResult{callID: h.toolCallID, name: h.toolName, content: output})
	h.toolCallID = ""
	h.toolName = ""
}

func (h *CallbacksHandler) HandleToolError(ctx context.Context, err error) {
	if h.toolCallID == "" {
		h.toolCallID = events.GenerateToolCallID()
	}
	slog.WarnContext(ctx, "callbacks: tool error", "toolCallID", h.toolCallID, "toolName", h.toolName, "error", err)
	h.send(events.NewToolCallResultEvent(events.GenerateMessageID(), h.toolCallID, "Error: "+err.Error()))
	h.send(events.NewToolCallEndEvent(h.toolCallID))
	h.toolResults = append(h.toolResults, toolResult{callID: h.toolCallID, name: h.toolName, content: "Error: " + err.Error()})
	h.toolCallID = ""
	h.toolName = ""
}

func (h *CallbacksHandler) HandleAgentAction(ctx context.Context, action schema.AgentAction) {
	// Close previous tool call if one is still active (agent starting a new action)
	if h.toolCallID != "" {
		h.send(events.NewToolCallEndEvent(h.toolCallID))
	}

	// Generate new tool call ID for this action
	h.toolCallID = events.GenerateToolCallID()
	h.toolName = action.Tool
	start := events.NewToolCallStartEvent(h.toolCallID, action.Tool)
	if h.messageID != "" {
		start = events.NewToolCallStartEvent(h.toolCallID, action.Tool, events.WithParentMessageID(h.messageID))
	}
	h.send(start)
	h.send(events.NewToolCallArgsEvent(h.toolCallID, action.ToolInput))
	slog.DebugContext(ctx, "callbacks: agent action", "toolCallID", h.toolCallID, "tool", action.Tool, "input_preview", action.ToolInput)
	if h.llmSpan != nil {
		// Set output message role
		h.llmSpan.SetAttributes(
			attribute.String("llm.output_messages.0.message.role", "assistant"),
		)
		// Set tool call attributes
		h.llmSpan.SetAttributes(
			attribute.String("llm.output_messages.0.message.tool_calls.0.tool_call.id", h.toolCallID),
			attribute.String("llm.output_messages.0.message.tool_calls.0.tool_call.function.name", action.Tool),
			attribute.String("llm.output_messages.0.message.tool_calls.0.tool_call.function.arguments", truncateTraceValue(action.ToolInput, maxSpanAttrLen)),
		)
	}
}

func (h *CallbacksHandler) HandleAgentFinish(ctx context.Context, finish schema.AgentFinish) {
	// Ensure any active things are closed before finishing
	h.finalizeRun()

	if finish.ReturnValues != nil {
		if output, ok := finish.ReturnValues["output"].(string); ok && output != "" {
			msgID := h.ensureMessageID()
			if !h.messageStarted {
				h.send(events.NewTextMessageStartEvent(msgID, events.WithRole("assistant")))
				h.messageStarted = true
			}
			h.send(events.NewTextMessageContentEvent(msgID, output))
			h.send(events.NewTextMessageEndEvent(msgID))
			h.messageStarted = false
		}
	}
	h.SendRunFinished()
}

func extractTokenUsage(res *llms.ContentResponse) (int64, int64, bool) {
	if res == nil {
		return 0, 0, false
	}
	v := reflect.ValueOf(res)
	if v.Kind() == reflect.Ptr {
		if v.IsNil() {
			return 0, 0, false
		}
		v = v.Elem()
	}
	if !v.IsValid() {
		return 0, 0, false
	}
	usage := v.FieldByName("Usage")
	if !usage.IsValid() {
		return 0, 0, false
	}
	if usage.Kind() == reflect.Ptr {
		if usage.IsNil() {
			return 0, 0, false
		}
		usage = usage.Elem()
	}
	inputTokens := getIntField(usage, "PromptTokens", "InputTokens", "PromptTokenCount")
	outputTokens := getIntField(usage, "CompletionTokens", "OutputTokens", "CompletionTokenCount")
	if inputTokens == 0 && outputTokens == 0 {
		return 0, 0, false
	}
	return inputTokens, outputTokens, true
}

func extractOutputText(res *llms.ContentResponse) string {
	if res == nil {
		return ""
	}
	v := reflect.ValueOf(res)
	if v.Kind() == reflect.Ptr {
		if v.IsNil() {
			return ""
		}
		v = v.Elem()
	}
	if !v.IsValid() {
		return ""
	}
	if content := readStringField(v, "Content", "Text"); content != "" {
		return content
	}
	if choiceText := readSliceStringField(v, "Choices", "Candidates"); choiceText != "" {
		return choiceText
	}
	return ""
}

func readStringField(v reflect.Value, names ...string) string {
	for _, name := range names {
		field := v.FieldByName(name)
		if !field.IsValid() {
			continue
		}
		if field.Kind() == reflect.Ptr {
			if field.IsNil() {
				continue
			}
			field = field.Elem()
		}
		if field.Kind() == reflect.String {
			return field.String()
		}
	}
	return ""
}

func readSliceStringField(v reflect.Value, names ...string) string {
	for _, name := range names {
		field := v.FieldByName(name)
		if !field.IsValid() || field.Kind() != reflect.Slice {
			continue
		}
		for i := 0; i < field.Len(); i++ {
			elem := field.Index(i)
			if elem.Kind() == reflect.Ptr {
				if elem.IsNil() {
					continue
				}
				elem = elem.Elem()
			}
			if elem.Kind() != reflect.Struct {
				continue
			}
			if text := readStringField(elem, "Content", "Text"); text != "" {
				return text
			}
			msg := elem.FieldByName("Message")
			if msg.IsValid() {
				if msg.Kind() == reflect.Ptr {
					if msg.IsNil() {
						continue
					}
					msg = msg.Elem()
				}
				if msg.Kind() == reflect.Struct {
					if text := readStringField(msg, "Content", "Text"); text != "" {
						return text
					}
				}
			}
		}
	}
	return ""
}

func getIntField(v reflect.Value, names ...string) int64 {
	for _, name := range names {
		field := v.FieldByName(name)
		if !field.IsValid() {
			continue
		}
		switch field.Kind() {
		case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
			return field.Int()
		case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
			return int64(field.Uint())
		case reflect.Float32, reflect.Float64:
			return int64(field.Float())
		}
	}
	return 0
}

// SendRunFinished sends a RunFinished event and marks the handler as finished so
// no further events are emitted for this run.
func (h *CallbacksHandler) SendRunFinished() {
	if h.runFinished {
		return
	}
	// Close any active things just in case
	h.finalizeRun()
	h.runFinished = true
	h.send(events.NewRunFinishedEvent(h.threadID, h.runID))
}

// finalizeRun closes active message, tool call, or step if any. It is safe to call
// multiple times and is used by non-agent branches before emitting RunFinished.
func (h *CallbacksHandler) finalizeRun() {
	if h.toolCallID != "" {
		h.send(events.NewToolCallEndEvent(h.toolCallID))
		h.toolCallID = ""
	}

	if h.stepID != "" {
		h.send(events.NewStepFinishedEvent(h.stepID))
		h.stepID = ""
	}

	if h.messageStarted && h.messageID != "" {
		h.send(events.NewTextMessageEndEvent(h.messageID))
		h.messageStarted = false
		// reset message ID for next interaction
		h.messageID = ""
	}
}

func (h *CallbacksHandler) HandleRetrieverStart(ctx context.Context, query string) {
	msgID := h.ensureMessageID()
	if !h.messageStarted {
		h.send(events.NewTextMessageStartEvent(msgID, events.WithRole("assistant")))
		h.messageStarted = true
	}
	h.send(events.NewTextMessageContentEvent(msgID, fmt.Sprintf("Searching for: %s", query)))
}

func (h *CallbacksHandler) HandleRetrieverEnd(ctx context.Context, query string, documents []schema.Document) {
	msgID := h.ensureMessageID()
	if !h.messageStarted {
		h.send(events.NewTextMessageStartEvent(msgID, events.WithRole("assistant")))
		h.messageStarted = true
	}
	h.send(events.NewTextMessageContentEvent(msgID, fmt.Sprintf("Found %d documents for query: %s", len(documents), query)))
}

func (h *CallbacksHandler) HandleStreamingFunc(ctx context.Context, chunk []byte) {
	msgID := h.ensureMessageID()
	if !h.messageStarted {
		h.send(events.NewTextMessageStartEvent(msgID, events.WithRole("assistant")))
		h.messageStarted = true
	}
	slog.DebugContext(ctx, "callbacks: streaming chunk", "msgID", msgID, "chunk_preview", string(chunk))
	h.send(events.NewTextMessageContentEvent(msgID, string(chunk)))
}
