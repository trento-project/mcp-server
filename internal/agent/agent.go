package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"

	"bytes"
	"io"
	"net/http"
	"time"

	"github.com/ag-ui-protocol/ag-ui/sdks/community/go/pkg/core/events"
	langchaingo_mcp_adapter "github.com/i2y/langchaingo-mcp-adapter"
	"github.com/mark3labs/mcp-go/client"
	transport "github.com/mark3labs/mcp-go/client/transport"
	"github.com/tmc/langchaingo/agents"
	"github.com/tmc/langchaingo/chains"
	"github.com/tmc/langchaingo/llms"
	"github.com/tmc/langchaingo/llms/googleai"
	"github.com/tmc/langchaingo/memory"
	"github.com/tmc/langchaingo/prompts"
	"github.com/trento-project/mcp-server/internal/rag"
	"github.com/trento-project/mcp-server/internal/telemetry"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/trace"

	langchaingoTools "github.com/tmc/langchaingo/tools"
)

// loggingTool is a small decorator to add request/response logging to MCP tools.
type loggingTool struct {
	inner   langchaingoTools.Tool
	metrics *telemetry.Metrics
	tracer  trace.Tracer
}

const maxSpanAttrLen = 8192

func truncateSpanAttr(value string) string {
	if len(value) <= maxSpanAttrLen {
		return value
	}
	return value[:maxSpanAttrLen] + "..."
}

func detectMimeType(value string) string {
	if strings.TrimSpace(value) == "" {
		return "text/plain"
	}
	var tmp any
	if json.Unmarshal([]byte(value), &tmp) == nil {
		return "application/json"
	}
	return "text/plain"
}

func (lt *loggingTool) Name() string { return lt.inner.Name() }

func (lt *loggingTool) Call(ctx context.Context, input string) (string, error) {
	start := time.Now()
	var span trace.Span
	if lt.tracer != nil {
		ctx, span = lt.tracer.Start(ctx, "tool.call", trace.WithAttributes(
			attribute.String("openinference.span.kind", "TOOL"),
			attribute.String("tool.name", lt.Name()),
			attribute.String("tool.input", truncateSpanAttr(input)),
			attribute.String("input.value", truncateSpanAttr(input)),
			attribute.String("input.mime_type", detectMimeType(input)),
		))
		defer span.End()
	}
	slog.DebugContext(ctx, "mcp-tool: call start", "tool", lt.Name(), "input_preview", input)
	res, err := lt.inner.Call(ctx, input)
	dur := time.Since(start)
	if lt.metrics != nil {
		attrs := metric.WithAttributes(attribute.String("tool.name", lt.Name()))
		lt.metrics.ToolCallCount.Add(ctx, 1, attrs)
		lt.metrics.ToolCallLatency.Record(ctx, float64(dur.Milliseconds()), attrs)
		if err != nil {
			lt.metrics.ToolErrorCount.Add(ctx, 1, attrs)
		}
	}
	if err != nil {
		slog.WarnContext(ctx, "mcp-tool: call error", "tool", lt.Name(), "duration_ms", dur.Milliseconds(), "error", err)
		if span != nil {
			span.RecordError(err)
			span.SetStatus(codes.Error, err.Error())
		}
		return res, err
	}
	if span != nil && res != "" {
		span.SetAttributes(
			attribute.String("tool.output", truncateSpanAttr(res)),
			attribute.String("output.value", truncateSpanAttr(res)),
			attribute.String("output.mime_type", detectMimeType(res)),
		)
	}
	// Log successful tool call with format indication
	var tmp any
	format := "text"
	if json.Unmarshal([]byte(res), &tmp) == nil {
		format = "json"
	}
	slog.DebugContext(ctx, "mcp-tool: call success", "tool", lt.Name(), "duration_ms", dur.Milliseconds(), "format", format)
	return res, nil
}

func (lt *loggingTool) Description() string {
	if d, ok := lt.inner.(interface{ Description() string }); ok {
		return d.Description()
	}
	return ""
}

// FrontendTool implements the langchaingo Tool interface for a tool defined at runtime on the frontend.
type FrontendTool struct {
	name        string
	description string
	parameters  map[string]any
}

func (t *FrontendTool) Name() string {
	// return fmt.Sprintf("frontend_tool_%s", t.name)
	return fmt.Sprintf("%s", t.name)
}

// Description formats the tool's description along with its parameters
// in a way that is understandable to the LLM.
func (t *FrontendTool) Description() string {
	paramBytes, err := json.Marshal(t.parameters)
	if err != nil || string(paramBytes) == "null" || string(paramBytes) == "{}" {
		return t.description
	}
	return fmt.Sprintf("%s. The tool parameters are a JSON object with the following schema: %s", t.description, string(paramBytes))
}

// Call is a no-op for frontend tools from the backend's perspective. It returns a success message
// assuming the frontend will pick up the tool call event and execute it.
func (t *FrontendTool) Call(ctx context.Context, input string) (string, error) {
	slog.DebugContext(ctx, "frontend-tool: call trigger", "tool", t.name, "input", input)
	// The agent executor will send a ToolInputEvent via the CallbacksHandler.
	// The frontend is expected to listen for this event and execute the tool.
	// This backend implementation does not wait for a result from the frontend.
	return fmt.Sprintf("Frontend tool '%s' called. The frontend is expected to handle the execution.", t.name), nil
}

// loggingRoundTripper is a transport that logs request/response details for MCP HTTP calls.
type loggingRoundTripper struct{ rt http.RoundTripper }

func (l *loggingRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	// Mask Authorization header for logs
	auth := req.Header.Get("Authorization")
	maskedAuth := ""
	if auth != "" {
		parts := strings.SplitN(auth, " ", 2)
		if len(parts) == 2 {
			tok := parts[1]
			if len(tok) > 6 {
				maskedAuth = parts[0] + " ****" + tok[len(tok)-4:]
			} else {
				maskedAuth = parts[0] + " ****"
			}
		} else {
			maskedAuth = "****"
		}
	}
	slog.DebugContext(req.Context(), "mcp-http: request", "method", req.Method, "url", req.URL.String(), "auth", maskedAuth)

	resp, err := l.rt.RoundTrip(req)
	if err != nil {
		slog.WarnContext(req.Context(), "mcp-http: request error", "error", err)
		return resp, err
	}

	var bodyBytes []byte
	if resp.Body != nil {
		bodyBytes, _ = io.ReadAll(resp.Body)
		// restore body for caller
		resp.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))
	}
	preview := ""
	if len(bodyBytes) > 0 {
		if len(bodyBytes) > 512 {
			preview = string(bodyBytes[:512])
		} else {
			preview = string(bodyBytes)
		}
	}
	slog.DebugContext(req.Context(), "mcp-http: response", "status", resp.StatusCode, "body_preview", preview)
	return resp, nil
}

const TRENTO_SYSTEM_PROMPT = `You are an expert AI assistant for SUSE Trento, a comprehensive solution for SAP applications management and monitoring.

## YOUR ROLE
You help users manage and monitor their SAP HANA and NetWeaver systems through the Trento platform. You provide clear, accurate guidance about:
- SAP system health and performance
- HANA cluster monitoring
- Best practices for SAP on SUSE Linux Enterprise Server
- Troubleshooting SAP-related issues
- Interpreting Trento checks and alerts

## CORE DIRECTIVES

### Context Awareness
* Always consider the user's current context (cluster, system, or resource being monitored)
* If context is missing, ask clarifying questions before taking action

### Building User Trust

1. **Reasoning Transparency**: Always explain why you reached a conclusion
   - Good: "The HANA cluster shows 3 failed checks. This indicates potential replication issues."
   - Bad: "The cluster is unhealthy."

2. **Confidence Indicators**: Express certainty levels clearly
   - High certainty: "This is definitively a configuration issue (95%)"
   - Likely: "This strongly suggests a memory problem (80%)"
   - Possible: "This could be network-related (60%)"

3. **Graceful Boundaries**
   - If an issue requires SAP expertise: "This requires SAP Basis administrator knowledge. Please consult your SAP team."
   - If off-topic: "I can't help with that, but I can explain how to monitor your HANA clusters."

## TOOL USAGE
* Always use the available MCP tools to query real Trento data
* If a tool fails, explain the failure and suggest manual steps
* For documentation questions, the RAG system will provide relevant context automatically
* When documentation context is provided, USE IT to answer comprehensively
* Synthesize information from retrieved documentation to give detailed, accurate answers

## DOCUMENTATION & RAG
* When documentation context is provided, use it to give comprehensive, detailed answers
* Extract and present complete step-by-step instructions from retrieved documentation when users ask "how to" questions
* Present installation, configuration, and setup procedures as clear numbered lists with all commands, prerequisites, and details
* Summarize procedures and requirements clearly from the provided context
* If retrieved context contains instructions, present them directly - do not just reference external links
* Always prefer information from retrieved documentation over general knowledge
* When providing information from docs, cite the source document name
* Do NOT say "the documentation doesn't contain specific instructions" when step-by-step procedures are clearly present in the retrieved context

## RESPONSE FORMAT
* Be concise and clear
* Provide actionable suggestions
* Format output in Markdown
* For system status, summarize first then provide details

## BEST PRACTICES
* Prioritize system health and data integrity
* Follow SAP and SUSE best practices
* Consider high-availability requirements
* Be aware of production system sensitivity`

// AgentService holds the initialized agent executor and underlying clients so it
// can be reused to answer multiple queries (e.g. from an AG-UI connection).
type AgentService struct {
	mcpClient    *client.Client
	mcpURL       string
	mcpAuthToken string
	llm          llms.Model
	llmModel     string
	tools        []langchaingoTools.Tool
	memory       *memory.ConversationBuffer
	systemPrompt string
	ragStore     *rag.RAGStore
	metrics      *telemetry.Metrics
	otelTracer   trace.Tracer
}

// composeInput builds the model input with system prompt, optional frontend context, and user info snapshot.
func (s *AgentService) composeInput(question, ctxBlob, userInfo string) string {
	base := strings.TrimSpace(question)
	sections := []string{}
	if userInfo != "" {
		sections = append(sections, fmt.Sprintf("User info (from tools):\n%s", userInfo))
	}
	if ctxBlob != "" {
		sections = append(sections, fmt.Sprintf("Frontend context (JSON):\n%s", ctxBlob))
	}
	sections = append(sections, fmt.Sprintf("User message:\n%s", base))
	return strings.Join(sections, "\n\n")
}

// emitRunError sends a run error event and returns the provided error.
func (s *AgentService) emitRunError(ctx context.Context, handler *CallbacksHandler, runID string, err error) error {
	if jsonData, e := events.NewRunErrorEvent(err.Error(), events.WithRunID(runID)).ToJSON(); e == nil {
		select {
		case handler.returnChan <- jsonData:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return err
}

// emitRunFinished closes the run explicitly (used for non-agent branches).
func (s *AgentService) emitRunFinished(ctx context.Context, handler *CallbacksHandler, threadID, runID string) error {
	// Use handler to set finished flag and send event consistently
	handler.SendRunFinished()
	return nil
}

// fetchUserInfo tries to call a user-related MCP tool once per run and returns the text, if any.
// If the tool call fails with a session-terminated style error, we attempt a single
// reset+retry to recover from MCP session expiration.
// func (s *AgentService) fetchUserInfo(ctx context.Context, handler *CallbacksHandler) string {
// 	var userTool langchaingoTools.Tool
// 	for _, t := range s.tools {
// 		name := strings.ToLower(t.Name())
// 		if strings.Contains(name, "user") || strings.Contains(name, "profile") || strings.Contains(name, "whoami") {
// 			userTool = t
// 			break
// 		}
// 	}
// 	if userTool == nil {
// 		slog.DebugContext(ctx, "fetchUserInfo: no user tool available")
// 		return ""
// 	}

// 	slog.DebugContext(ctx, "fetchUserInfo: calling tool", "tool", userTool.Name())
// 	handler.HandleToolStart(ctx, "fetch_user_context")

// 	// Try once, and retry a single time if the error looks like a session termination.
// 	result, err := userTool.Call(ctx, "{}")
// 	if err != nil {
// 		handler.HandleToolError(ctx, err)
// 		// Detect common session-terminated symptom and attempt one reset+retry.
// 		errStr := strings.ToLower(err.Error())
// 		if strings.Contains(errStr, "session terminated") || strings.Contains(errStr, "404") {
// 			slog.WarnContext(ctx, "fetchUserInfo: session error detected; resetting tools and retrying", "error", err)
// 			s.resetTools()
// 			if e := s.ensureTools(ctx); e == nil {
// 				// locate user tool again
// 				for _, t := range s.tools {
// 					name := strings.ToLower(t.Name())
// 					if strings.Contains(name, "user") || strings.Contains(name, "profile") || strings.Contains(name, "whoami") {
// 						userTool = t
// 						break
// 					}
// 				}
// 				if userTool != nil {
// 					res2, err2 := userTool.Call(ctx, "{}")
// 					if err2 == nil {
// 						handler.HandleToolEnd(ctx, res2)
// 						slog.DebugContext(ctx, "fetchUserInfo: tool result (retry)", "tool", userTool.Name(), "result", res2)
// 						return strings.TrimSpace(res2)
// 					}
// 					handler.HandleToolError(ctx, err2)
// 					slog.WarnContext(ctx, "fetchUserInfo: retry failed", "error", err2)
// 				}
// 			}
// 			return ""
// 		}

// 		slog.WarnContext(ctx, "fetchUserInfo: tool call failed", "tool", userTool.Name(), "error", err)
// 		return ""
// 	}
// 	handler.HandleToolEnd(ctx, result)
// 	slog.DebugContext(ctx, "fetchUserInfo: tool result", "tool", userTool.Name(), "result", result)
// 	return strings.TrimSpace(result)
// }

type plannerDecision struct {
	Action string `json:"action"`
	Reason string `json:"reason,omitempty"`
	Tool   string `json:"tool,omitempty"`
}

// planRoute decides how to respond: direct LLM, MCP tools, RAG placeholder, or ask for more info.
func (s *AgentService) planRoute(ctx context.Context, composedInput, ctxBlob, userInfo string, handler *CallbacksHandler) plannerDecision {
	// helper to extract JSON from text (strips code fences and surrounding text)
	// returns original text if JSON object braces cannot be found
	if s == nil {
		// just to satisfy static analysis (never nil in practice)
	}

	// helper function defined on the receiver for ease of testing/mocking
	// It attempts to find a JSON object inside free text, handling code fences like ```json
	// If a JSON object is found, it returns the JSON substring, otherwise returns original input.
	// Examples handled:
	// ```json
	// {"action":"mcp_tool"}
	// ```
	// or plain {
	//   ...
	// }
	// or text ... { ... } ... text
	// The function returns the substring starting at first '{' and ending at matching '}'.
	// It's simple but robust for common LLM outputs.
	// Note: keep it small to avoid dependencies.
	//
	// We implement it as a local closure to keep encapsulation.
	extractJSON := func(text string) string {
		text = strings.TrimSpace(text)
		// Remove fenced block markers if present
		if strings.HasPrefix(text, "```") {
			// remove leading fence line
			idx := strings.Index(text, "\n")
			if idx != -1 {
				text = strings.TrimSpace(text[idx+1:])
			}
			// remove trailing fences
			if strings.HasSuffix(text, "```") {
				text = strings.TrimSpace(text[:len(text)-3])
			}
		}
		// Try to find first JSON object by braces
		first := strings.Index(text, "{")
		last := strings.LastIndex(text, "}")
		if first != -1 && last != -1 && last > first {
			candidate := strings.TrimSpace(text[first : last+1])
			return candidate
		}
		return text
	}

	prompt := prompts.NewPromptTemplate(
		`You are a routing planner. Decide one best next action for the assistant.
Options:
- ask_more: ask the user for a clarifying question.
- direct_answer: respond directly with the LLM without tools.
- mcp_tool: use available MCP tools to query real-time Trento system data.
- rag_tool: use RAG retrieval for documentation, best practices, and how-to questions.
- frontend_tool: a frontend tool.

Guidelines:
- Use rag_tool for: installation instructions, configuration guides, setup procedures, documentation, how-to guides, best practices, explanations about Trento features, requirements, architecture, troubleshooting steps
- Use mcp_tool for: real-time system status, cluster health, current checks, active alerts, monitoring data, specific SAP system information
- Use direct_answer for: greetings, simple acknowledgments, general questions not needing tools or documentation

IMPORTANT: Questions containing words like "install", "configure", "setup", "how to", "requirements", "deploy", "update", "upgrade" should use rag_tool.
Questions about "current status", "health", "alerts", "running systems", "check results" should use mcp_tool.

Consider user info and frontend context only as supplementary information.
Return only JSON: {"action": "ask_more|direct_answer|mcp_tool|rag_tool|frontend_tool", "reason": "..."}.

Context:
{{ .context }}

Composed input:
{{ .input }}
`, []string{"context", "input"})

	vals := map[string]any{
		"context": userInfo + "\n" + ctxBlob,
		"input":   composedInput,
	}

	planChain := chains.NewLLMChain(s.llm, prompt)
	slog.DebugContext(ctx, "planner: calling LLM chain", "context_preview", vals["context"], "input_preview", vals["input"])
	// Manually trigger LLM callbacks
	handler.llmSystemPrompt = prompt.Template
	tracePrompt := fmt.Sprintf("Context: %s\nInput: %s", vals["context"], vals["input"])
	if rendered, err := prompt.Format(vals); err == nil {
		tracePrompt = fmt.Sprintf("TEMPLATE:\n%s\n\nRENDERED:\n%s", prompt.Template, rendered)
	}
	handler.HandleLLMStart(ctx, []string{tracePrompt})
	out, err := chains.Call(ctx, planChain, vals)
	if err != nil {
		slog.WarnContext(ctx, "planner error; defaulting to mcp_tool", "error", err)
		handler.HandleLLMError(ctx, err)
		return plannerDecision{Action: "mcp_tool", Reason: "planner_error"}
	}
	// Extract output and close LLM span
	slog.DebugContext(ctx, "planner: raw output", "output_map", out)
	outputKeys := planChain.GetOutputKeys()
	if len(outputKeys) == 0 {
		slog.WarnContext(ctx, "planner returned no outputs; defaulting to mcp_tool")
		return plannerDecision{Action: "mcp_tool", Reason: "no_output_keys"}
	}
	raw := out[outputKeys[0]]
	var sraw string
	if r, ok := raw.(string); ok {
		sraw = strings.TrimSpace(r)
	} else {
		sraw = strings.TrimSpace(fmt.Sprint(raw))
	}
	slog.DebugContext(ctx, "planner: raw output string", "sraw", sraw)
	// Sanitize planner output: strip markdown code fences or any leading explanation
	sanitized := extractJSON(sraw)
	if sanitized != sraw {
		slog.DebugContext(ctx, "planner: sanitized output", "sanitized", sanitized)
	}
	var decision plannerDecision
	if err := json.Unmarshal([]byte(sanitized), &decision); err != nil {
		slog.WarnContext(ctx, "planner parse error; defaulting to mcp_tool", "error", err, "raw", sraw, "sanitized", sanitized)
		// As a fallback, try to extract a simple action by scanning for known keywords
		low := strings.ToLower(sraw)
		if strings.Contains(low, "ask_more") || strings.Contains(low, "ask for") || strings.Contains(low, "clarify") {
			return plannerDecision{Action: "ask_more", Reason: "fallback_keyword"}
		}
		if strings.Contains(low, "mcp") || strings.Contains(low, "tool") || strings.Contains(low, "trento") {
			return plannerDecision{Action: "mcp_tool", Reason: "fallback_keyword"}
		}
		if strings.Contains(low, "frontend_tool") || strings.Contains(low, "frontend") {
			return plannerDecision{Action: "frontend_tool", Reason: "fallback_keyword"}
		}
		return plannerDecision{Action: "mcp_tool", Reason: "planner_parse_error"}
	}
	if decision.Action == "" {
		decision.Action = "mcp_tool"
	}
	// Close LLM span
	handler.llmOutput = sraw
	handler.HandleLLMGenerateContentEnd(ctx, &llms.ContentResponse{})
	return decision
}

// reconcileDecisionWithAvailability adjusts a plannerDecision when MCP tools are not available.
// If the planner requested an MCP tool but tools are unavailable, we fall back to a direct LLM answer.
func (s *AgentService) reconcileDecisionWithAvailability(dec plannerDecision, toolsAvailable bool) plannerDecision {
	if !toolsAvailable && dec.Action == "mcp_tool" {
		if dec.Reason == "" {
			dec.Reason = "tools_unavailable"
		} else {
			dec.Reason = dec.Reason + ";tools_unavailable"
		}
		dec.Action = "direct_answer"
	}
	return dec
}

// NewAgentService creates and initializes the agent and returns a reusable service.
// mcpURL is the MCP server URL to connect to (e.g. "http://localhost:5000").
func NewAgentService(ctx context.Context, mcpURL string, mcpAuthToken string, systemPrompt string, geminiAPIKey string, pgURL string, metrics *telemetry.Metrics, otelTracer trace.Tracer) (*AgentService, error) {
	// Install HTTP transport-level logger so any MCP client created later will have request/response traces.
	oldTransport := http.DefaultTransport
	http.DefaultTransport = &loggingRoundTripper{rt: oldTransport}

	// Do not create MCP client or fetch tools at startup; do it lazily to avoid stale connections.
	// Save connection info for later use.
	if strings.TrimSpace(systemPrompt) == "" {
		systemPrompt = TRENTO_SYSTEM_PROMPT
	}

	// Create an LLM client
	model := "gemini-2.5-flash"
	llm, err := googleai.New(
		ctx,
		googleai.WithAPIKey(geminiAPIKey),
		googleai.WithDefaultModel(model),
	)
	if err != nil {
		return nil, fmt.Errorf("create LLM client: %w", err)
	}

	history := memory.NewChatMessageHistory()
	conversationMemory := memory.NewConversationBuffer(memory.WithChatHistory(history))

	// Initialize RAG store if pgURL is provided
	var ragStore *rag.RAGStore
	if pgURL != "" {
		slog.InfoContext(ctx, "initializing RAG store", "pg_url", maskPgPassword(pgURL))
		embedder, err := rag.NewGeminiEmbedderWithTracer(ctx, geminiAPIKey, otelTracer)
		if err != nil {
			slog.WarnContext(ctx, "failed to create RAG embedder; RAG will be disabled", "error", err)
		} else {
			ragStore, err = rag.NewRAGStoreWithTracer(ctx, pgURL, embedder, otelTracer)
			if err != nil {
				slog.WarnContext(ctx, "failed to create RAG store; RAG will be disabled", "error", err)
			} else {
				slog.InfoContext(ctx, "RAG store initialized successfully")
			}
		}
	}

	return &AgentService{
		mcpClient:    nil,
		mcpURL:       mcpURL,
		mcpAuthToken: mcpAuthToken,
		llm:          llm,
		llmModel:     model,
		tools:        nil,
		memory:       conversationMemory,
		systemPrompt: systemPrompt,
		ragStore:     ragStore,
		metrics:      metrics,
		otelTracer:   otelTracer,
	}, nil
}

// maskPgPassword masks the password in a PostgreSQL connection URL for logging
func maskPgPassword(url string) string {
	if idx := strings.Index(url, "://"); idx != -1 {
		after := url[idx+3:]
		if atIdx := strings.Index(after, "@"); atIdx != -1 {
			before := after[:atIdx]
			if colonIdx := strings.Index(before, ":"); colonIdx != -1 {
				return url[:idx+3] + before[:colonIdx+1] + "****" + after[atIdx:]
			}
		}
	}
	return url
}

// ensureTools lazily initializes the MCP client and fetches tools from the MCP server.
// It also verifies we have a live client so we don't reuse stale tools after the
// underlying session has been terminated by the server.
func (s *AgentService) ensureTools(ctx context.Context) error {
	// Quick health-check of existing client/tools: try to re-list tools using the
	// current client. If that fails we reset and recreate a fresh client/tools set.
	if s.mcpClient != nil && len(s.tools) > 0 {
		if adapter, err := langchaingo_mcp_adapter.New(s.mcpClient); err == nil {
			if _, err := adapter.Tools(); err == nil {
				// existing client and tools appear healthy
				return nil
			}
			// health check failed -> reset and fall through to recreate
			slog.WarnContext(ctx, "ensureTools: existing client/tools health check failed; resetting", "error", err)
			s.resetTools()
		} else {
			slog.WarnContext(ctx, "ensureTools: failed to create adapter from existing client; resetting", "error", err)
			s.resetTools()
		}
	}

	var err error
	var mcpClient *client.Client
	if s.mcpAuthToken != "" {
		headers := map[string]string{"Authorization": "Bearer " + s.mcpAuthToken}
		mcpClient, err = client.NewStreamableHttpClient(
			s.mcpURL,
			transport.WithHTTPHeaders(headers),
		)
	} else {
		mcpClient, err = client.NewStreamableHttpClient(
			s.mcpURL,
		)
	}
	if err != nil {
		return fmt.Errorf("failed to create MCP client: %w", err)
	}

	adapter, err := langchaingo_mcp_adapter.New(mcpClient)
	if err != nil {
		mcpClient.Close()
		return fmt.Errorf("failed to create adapter: %w", err)
	}

	mcpTools, err := adapter.Tools()
	if err != nil {
		mcpClient.Close()
		return fmt.Errorf("failed to get tools: %w", err)
	}

	// Wrap tools with logging decorator to capture calls and responses
	for i, t := range mcpTools {
		mcpTools[i] = &loggingTool{inner: t, metrics: s.metrics, tracer: s.otelTracer}
	}

	s.mcpClient = mcpClient
	s.tools = mcpTools
	for _, t := range s.tools {
		slog.DebugContext(ctx, "mcp tool registered (lazy)", "name", t.Name())
	}
	return nil
}

// buildToolSchemas converts langchaingo tools to OpenInference JSON schemas
func buildToolSchemas(tools []langchaingoTools.Tool) []string {
	schemas := make([]string, 0, len(tools))
	for _, tool := range tools {
		schema := map[string]any{
			"type": "function",
			"function": map[string]any{
				"name":        tool.Name(),
				"description": tool.Description(),
				"parameters": map[string]any{
					"type":       "object",
					"properties": map[string]any{},
				},
			},
		}

		// Try to extract parameters from tool description if available
		// Most langchaingo tools don't expose structured parameters,
		// so we provide a minimal schema
		if desc := tool.Description(); desc != "" {
			// Add description to the function
			funcMap := schema["function"].(map[string]any)
			funcMap["description"] = desc
		}

		b, err := json.Marshal(schema)
		if err == nil {
			schemas = append(schemas, string(b))
		}
	}
	return schemas
}

// ExecuteWithStreaming runs the agent on a question and streams AG-UI protocol events
// through the provided channel. This is used for SSE/AG-UI streaming responses.
// The agent maintains conversation history through memory.
func (s *AgentService) ExecuteWithStreaming(ctx context.Context, eventChan chan<- json.RawMessage, threadID, runID, messageID string, question string, frontendContext []any, frontendTools []any) error {
	// Start tracing and timing for the overall agent execution
	runStart := time.Now()
	defer func() {
		if s.metrics != nil {
			s.metrics.AgentExecutionLatency.Record(ctx, float64(time.Since(runStart).Milliseconds()))
		}
	}()
	var agentSpan trace.Span
	if s.otelTracer != nil {
		ctx, agentSpan = s.otelTracer.Start(ctx, "agent.execute", trace.WithAttributes(
			attribute.String("openinference.span.kind", "AGENT"),
			attribute.String("agent.run_id", runID),
			attribute.String("agent.question", question),
			attribute.String("input.value", truncateSpanAttr(question)),
			attribute.String("input.mime_type", "text/plain"),
			attribute.String("session.id", threadID),
		))
		defer agentSpan.End()
	}

	// Send RUN_STARTED immediately as required by AG-UI protocol
	if jsonData, err := events.NewRunStartedEvent(threadID, runID).ToJSON(); err == nil {
		select {
		case eventChan <- jsonData:
		case <-ctx.Done():
			return ctx.Err()
		}
	}

	// Ensure tools are initialized early so context/tool fetching works
	toolsAvailable := true
	if err := s.ensureTools(ctx); err != nil {
		slog.WarnContext(ctx, "failed to initialize MCP tools; falling back to LLM-only mode", "error", err)
		// Mark tools as unavailable and continue with an LLM-only fallback.
		toolsAvailable = false
		// Inform the user non-fatally so the frontend knows what's happening.
		// handler.HandleText(ctx, "Note: backend tools are temporarily unavailable — proceeding with an LLM-only response.")
		// DO NOT end the run here; continue so the assistant can still respond using the LLM.
	}

	// Combine backend and frontend tools
	allTools := make([]langchaingoTools.Tool, len(s.tools))
	copy(allTools, s.tools)

	for _, ftAny := range frontendTools {
		ftMap, ok := ftAny.(map[string]any)
		if !ok {
			slog.WarnContext(ctx, "skipping invalid frontend tool: not a map")
			continue
		}

		name, ok := ftMap["name"].(string)
		if !ok || name == "" {
			slog.WarnContext(ctx, "skipping invalid frontend tool: missing name")
			continue
		}

		desc, _ := ftMap["description"].(string)

		params, _ := ftMap["parameters"].(map[string]any)

		slog.DebugContext(ctx, "registering frontend tool", "name", name)
		allTools = append(allTools, &FrontendTool{
			name:        name,
			description: desc,
			parameters:  params,
		})
	}

	// Build tool schemas for OpenInference tracing
	toolSchemas := buildToolSchemas(allTools)

	// Build handler per request so callbacks stream events
	handler := NewCallbacksHandler(eventChan, threadID, runID, messageID, s.metrics, s.otelTracer, s.llmModel, toolSchemas)

	// Create agent with all tools
	agent := agents.NewConversationalAgent(s.llm, allTools)

	executor := agents.NewExecutor(
		agent,
		agents.WithMemory(s.memory),
		agents.WithCallbacksHandler(handler),
		agents.WithMaxIterations(6),
		agents.WithReturnIntermediateSteps(),
	)

	// Build augmented input with configurable system prompt, frontend context, and optional user info
	input := strings.TrimSpace(question)
	ctxBlob := ""
	if frontendContext != nil {
		if b, err := json.Marshal(frontendContext); err == nil && len(b) > 2 {
			ctxBlob = string(b)
		}
	}
	// userInfo := s.fetchUserInfo(ctx, handler)
	userInfo := ""
	input = s.composeInput(input, ctxBlob, userInfo)

	// Update agent span with composed input
	if agentSpan != nil {
		agentSpan.SetAttributes(attribute.String("input.value", truncateSpanAttr(input)))
	}

	slog.DebugContext(ctx, "agent: running planner", "threadID", threadID, "userInfo", userInfo, "ctxBlob_preview", ctxBlob)

	// Trace planning phase
	if s.otelTracer != nil {
		ctx2, planningSpan := s.otelTracer.Start(ctx, "agent.planning", trace.WithAttributes(
			attribute.String("openinference.span.kind", "CHAIN"),
			attribute.String("input.value", truncateSpanAttr(input)),
			attribute.String("input.mime_type", "text/plain"),
		))
		decision := s.planRoute(ctx2, input, ctxBlob, userInfo, handler)

		// Set output with decision JSON
		if decisionJSON, err := json.Marshal(decision); err == nil {
			planningSpan.SetAttributes(
				attribute.String("output.value", string(decisionJSON)),
				attribute.String("output.mime_type", "application/json"),
			)
		}
		planningSpan.SetStatus(codes.Ok, "planning completed")
		planningSpan.End()
		decision = s.reconcileDecisionWithAvailability(decision, toolsAvailable)
		if decision.Reason != "" && strings.Contains(decision.Reason, "tools_unavailable") {
			slog.WarnContext(ctx, "planner requested MCP tools but none are available; falling back to direct_answer", "threadID", threadID, "runID", runID)
			if s.metrics != nil {
				s.metrics.DecisionFallback.Add(ctx, 1)
			}
		}
		slog.DebugContext(ctx, "agent: planner decision", "threadID", threadID, "runID", runID, "action", decision.Action, "reason", decision.Reason, "tool", decision.Tool)

		// Record decision metrics
		if s.metrics != nil {
			switch decision.Action {
			case "direct_answer":
				s.metrics.DecisionDirectAnswer.Add(ctx, 1)
			case "mcp_tool":
				s.metrics.DecisionMCPTool.Add(ctx, 1)
			}
		}

		// Execute based on decision
		var finalOutput string
		var err error
		switch decision.Action {
		case "direct_answer":
			finalOutput, err = s.executeDirectAnswerPath(ctx, handler, input, threadID, runID)
			if err != nil {
				if s.metrics != nil {
					s.metrics.AgentErrorCount.Add(ctx, 1)
				}
				if agentSpan != nil {
					agentSpan.SetStatus(codes.Error, err.Error())
				}
				return err
			}
			if s.metrics != nil {
				s.metrics.AgentSuccessCount.Add(ctx, 1)
			}

		case "mcp_tool":
			finalOutput, err = s.executeMCPToolPath(ctx, handler, executor, input, threadID, runID)
			if err != nil {
				if s.metrics != nil {
					s.metrics.AgentErrorCount.Add(ctx, 1)
				}
				if agentSpan != nil {
					agentSpan.SetStatus(codes.Error, err.Error())
				}
				return err
			}
			if s.metrics != nil {
				s.metrics.AgentSuccessCount.Add(ctx, 1)
			}

		case "rag_tool":
			finalOutput, err = s.executeRAGPath(ctx, handler, question, input, threadID, runID)
			if err != nil {
				if s.metrics != nil {
					s.metrics.AgentErrorCount.Add(ctx, 1)
				}
				if agentSpan != nil {
					agentSpan.SetStatus(codes.Error, err.Error())
				}
				return err
			}
			if s.metrics != nil {
				s.metrics.AgentSuccessCount.Add(ctx, 1)
			}

		default:
			// Default to direct answer
			finalOutput, err = s.executeDirectAnswerPath(ctx, handler, input, threadID, runID)
			if err != nil {
				if s.metrics != nil {
					s.metrics.AgentErrorCount.Add(ctx, 1)
				}
				if agentSpan != nil {
					agentSpan.SetStatus(codes.Error, err.Error())
				}
				return err
			}
			if s.metrics != nil {
				s.metrics.AgentSuccessCount.Add(ctx, 1)
			}
		}

		// Set output on agent span
		if agentSpan != nil && finalOutput != "" {
			agentSpan.SetAttributes(
				attribute.String("output.value", truncateSpanAttr(finalOutput)),
				attribute.String("output.mime_type", "text/plain"),
			)
			agentSpan.SetStatus(codes.Ok, "execution completed")
		}
		return nil
	}

	// Fallback without tracing (legacy path)
	decision := s.planRoute(ctx, input, ctxBlob, userInfo, handler)
	decision = s.reconcileDecisionWithAvailability(decision, toolsAvailable)
	if decision.Reason != "" && strings.Contains(decision.Reason, "tools_unavailable") {
		slog.WarnContext(ctx, "planner requested MCP tools but none are available; falling back to direct_answer", "threadID", threadID, "runID", runID)
		if s.metrics != nil {
			s.metrics.DecisionFallback.Add(ctx, 1)
		}
	}
	slog.DebugContext(ctx, "agent: planner decision", "threadID", threadID, "runID", runID, "action", decision.Action, "reason", decision.Reason, "tool", decision.Tool)

	// Record decision metrics
	if s.metrics != nil {
		switch decision.Action {
		case "direct_answer":
			s.metrics.DecisionDirectAnswer.Add(ctx, 1)
		case "mcp_tool":
			s.metrics.DecisionMCPTool.Add(ctx, 1)
		}
	}

	var finalOutput string
	var err error
	switch decision.Action {
	case "direct_answer":
		finalOutput, err = s.executeDirectAnswerPath(ctx, handler, input, threadID, runID)
		if err != nil {
			if s.metrics != nil {
				s.metrics.AgentErrorCount.Add(ctx, 1)
			}
			return err
		}
		if s.metrics != nil {
			s.metrics.AgentSuccessCount.Add(ctx, 1)
		}

	case "mcp_tool":
		finalOutput, err = s.executeMCPToolPath(ctx, handler, executor, input, threadID, runID)
		if err != nil {
			if s.metrics != nil {
				s.metrics.AgentErrorCount.Add(ctx, 1)
			}
			return err
		}
		if s.metrics != nil {
			s.metrics.AgentSuccessCount.Add(ctx, 1)
		}

	case "rag_tool":
		finalOutput, err = s.executeRAGPath(ctx, handler, question, input, threadID, runID)
		if err != nil {
			if s.metrics != nil {
				s.metrics.AgentErrorCount.Add(ctx, 1)
			}
			return err
		}
		if s.metrics != nil {
			s.metrics.AgentSuccessCount.Add(ctx, 1)
		}

	default:
		// Default to direct answer
		finalOutput, err = s.executeDirectAnswerPath(ctx, handler, input, threadID, runID)
		if err != nil {
			if s.metrics != nil {
				s.metrics.AgentErrorCount.Add(ctx, 1)
			}
			return err
		}
		if s.metrics != nil {
			s.metrics.AgentSuccessCount.Add(ctx, 1)
		}
	}

	// Set output on agent span
	if agentSpan != nil && finalOutput != "" {
		agentSpan.SetAttributes(
			attribute.String("output.value", truncateSpanAttr(finalOutput)),
			attribute.String("output.mime_type", "text/plain"),
		)
		agentSpan.SetStatus(codes.Ok, "execution completed")
	}
	return nil
}

// executeDirectAnswerPath handles the direct answer route
func (s *AgentService) executeDirectAnswerPath(ctx context.Context, handler *CallbacksHandler, input, threadID, runID string) (string, error) {
	inputPrompt := input
	if strings.TrimSpace(s.systemPrompt) != "" {
		inputPrompt = fmt.Sprintf("%s\n\n%s", s.systemPrompt, input)
	}
	var directSpan trace.Span
	if s.otelTracer != nil {
		ctx, directSpan = s.otelTracer.Start(ctx, "agent.direct_answer", trace.WithAttributes(
			attribute.String("openinference.span.kind", "CHAIN"),
			attribute.String("input.value", truncateSpanAttr(inputPrompt)),
			attribute.String("input.mime_type", "text/plain"),
		))
		defer directSpan.End()
	}

	conv := chains.NewConversation(s.llm, s.memory)
	slog.DebugContext(ctx, "agent: direct_answer start", "threadID", threadID, "runID", runID, "input_preview", input)

	// Manually trigger LLM callbacks to create LLM span
	handler.llmSystemPrompt = s.systemPrompt
	handler.HandleLLMStart(ctx, []string{inputPrompt})

	output, err := chains.Run(ctx, conv, inputPrompt, chains.WithStreamingFunc(func(ctx context.Context, chunk []byte) error {
		handler.HandleStreamingFunc(ctx, chunk)
		return nil
	}))
	if err != nil {
		slog.WarnContext(ctx, "direct answer error", "error", err)
		handler.HandleLLMError(ctx, err)
		if directSpan != nil {
			directSpan.SetStatus(codes.Error, err.Error())
		}
		return "", s.emitRunError(ctx, handler, runID, err)
	}
	slog.DebugContext(ctx, "agent: direct_answer completed", "threadID", threadID, "runID", runID)

	// Set output on span
	if directSpan != nil {
		directSpan.SetAttributes(
			attribute.String("output.value", truncateSpanAttr(output)),
			attribute.String("output.mime_type", "text/plain"),
		)
		directSpan.SetStatus(codes.Ok, "direct answer completed")
	}

	// Close any active message before finishing the run to avoid AG-UI errors
	handler.llmOutput = output
	handler.HandleLLMGenerateContentEnd(ctx, &llms.ContentResponse{})
	return output, s.emitRunFinished(ctx, handler, threadID, runID)
}

// executeMCPToolPath handles the MCP tool route
func (s *AgentService) executeMCPToolPath(ctx context.Context, handler *CallbacksHandler, executor *agents.Executor, input, threadID, runID string) (string, error) {
	inputPrompt := input
	if strings.TrimSpace(s.systemPrompt) != "" {
		inputPrompt = fmt.Sprintf("%s\n\n%s", s.systemPrompt, input)
	}
	var mcpSpan trace.Span
	if s.otelTracer != nil {
		ctx, mcpSpan = s.otelTracer.Start(ctx, "agent.mcp_tool", trace.WithAttributes(
			attribute.String("openinference.span.kind", "CHAIN"),
			attribute.String("input.value", truncateSpanAttr(inputPrompt)),
			attribute.String("input.mime_type", "text/plain"),
		))
		defer mcpSpan.End()
	}

	// Use standard "input" key for executor calls
	vals := map[string]any{"input": inputPrompt}

	slog.DebugContext(ctx, "agent: calling mcp_tool executor", "agent", "mcp_tool", "threadID", threadID, "runID", runID)
	handler.llmSystemPrompt = s.systemPrompt
	out, err := chains.Call(ctx, executor, vals)
	if err != nil {
		errStr := err.Error()
		errStrLower := strings.ToLower(errStr)

		// Check for input validation errors (configuration issue)
		if strings.Contains(errStrLower, "invalid input values") || strings.Contains(errStrLower, "multiple keys") {
			slog.ErrorContext(ctx, "executor configuration error", "error", err, "vals", vals)
			handler.finalizeRun()
			handler.HandleText(ctx, "I encountered a configuration issue. Please contact your administrator.")
			handler.HandleLLMGenerateContentEnd(ctx, &llms.ContentResponse{})
			if mcpSpan != nil {
				mcpSpan.SetStatus(codes.Error, "configuration error")
			}
			s.emitRunFinished(ctx, handler, threadID, runID)
			return "", nil
		}

		// Check if this is a parsing error - agent produced free-form text instead of structured output
		if strings.Contains(errStrLower, "unable to parse agent output") {
			// Extract the actual content between "unable to parse agent output: " and the next error marker
			prefix := "unable to parse agent output: "
			if idx := strings.Index(errStrLower, prefix); idx >= 0 {
				content := errStr[idx+len(prefix):]
				// Remove any trailing error repetitions or error suffixes
				if endIdx := strings.Index(content, "I couldn't retrieve"); endIdx > 0 {
					content = content[:endIdx]
				}
				// Clean up any duplicate text
				content = strings.TrimSpace(content)
				if content != "" {
					slog.InfoContext(ctx, "agent produced free-form response; extracting useful content", "content_preview", content)
					handler.finalizeRun()
					handler.HandleText(ctx, content)
					handler.HandleLLMGenerateContentEnd(ctx, &llms.ContentResponse{})
					if mcpSpan != nil {
						mcpSpan.SetStatus(codes.Ok, "free-form response extracted")
					}
					return content, s.emitRunFinished(ctx, handler, threadID, runID)
				}
			}
		}

		// Graceful handling: convert tool/agent errors into a user-facing assistant message
		slog.WarnContext(ctx, "tool agent error; showing generic error", "error", err, "toolName", handler.toolName)
		handler.finalizeRun()
		handler.HandleText(ctx, "I encountered an issue retrieving that information. Please try again or rephrase your question.")
		handler.HandleLLMGenerateContentEnd(ctx, &llms.ContentResponse{})
		if mcpSpan != nil {
			mcpSpan.SetStatus(codes.Error, err.Error())
		}
		s.emitRunFinished(ctx, handler, threadID, runID)
		return "", nil
	}

	// Extract output string from map
	outputStr := ""
	if outputVal, ok := out["output"]; ok {
		if str, ok := outputVal.(string); ok {
			outputStr = str
		}
	}

	// Set output on span
	if mcpSpan != nil && outputStr != "" {
		mcpSpan.SetAttributes(
			attribute.String("output.value", truncateSpanAttr(outputStr)),
			attribute.String("output.mime_type", "text/plain"),
		)
		mcpSpan.SetStatus(codes.Ok, "mcp tool completed")
	}

	slog.DebugContext(ctx, "agent: mcp_tool output", "agent", "mcp_tool", "threadID", threadID, "runID", runID, "output", out)
	return outputStr, nil // run finished emitted by agent callbacks
}

// executeRAGPath handles the RAG route
func (s *AgentService) executeRAGPath(ctx context.Context, handler *CallbacksHandler, question, input, threadID, runID string) (string, error) {
	var ragSpan trace.Span
	if s.otelTracer != nil {
		ctx, ragSpan = s.otelTracer.Start(ctx, "agent.rag_tool", trace.WithAttributes(
			attribute.String("openinference.span.kind", "CHAIN"),
			attribute.String("input.value", truncateSpanAttr(input)),
			attribute.String("input.mime_type", "text/plain"),
		))
		defer ragSpan.End()
	}

	if s.ragStore == nil {
		slog.WarnContext(ctx, "RAG requested but not available; falling back to direct answer")
		conv := chains.NewConversation(s.llm, s.memory)
		// Manually trigger LLM callbacks
		handler.llmSystemPrompt = s.systemPrompt
		handler.HandleLLMStart(ctx, []string{input})
		output, err := chains.Run(ctx, conv, input, chains.WithStreamingFunc(func(ctx context.Context, chunk []byte) error {
			handler.HandleStreamingFunc(ctx, chunk)
			return nil
		}))
		if err != nil {
			slog.WarnContext(ctx, "direct answer error", "error", err)
			handler.HandleLLMError(ctx, err)
			if ragSpan != nil {
				inputPrompt := input
				if strings.TrimSpace(s.systemPrompt) != "" {
					inputPrompt = fmt.Sprintf("%s\n\n%s", s.systemPrompt, input)
				}
				handler.llmSystemPrompt = s.systemPrompt
				handler.HandleLLMStart(ctx, []string{inputPrompt})
			}
			return "", s.emitRunError(ctx, handler, runID, err)
		}

		// Set output on span
		if ragSpan != nil {
			ragSpan.SetAttributes(
				attribute.String("output.value", truncateSpanAttr(output)),
				attribute.String("output.mime_type", "text/plain"),
			)
			ragSpan.SetStatus(codes.Ok, "rag fallback completed")
		}

		handler.llmOutput = output
		handler.HandleLLMGenerateContentEnd(ctx, &llms.ContentResponse{})
		return output, s.emitRunFinished(ctx, handler, threadID, runID)
	}

	slog.DebugContext(ctx, "agent: using RAG for documentation retrieval", "threadID", threadID, "runID", runID)
	handler.HandleToolStart(ctx, "rag_retrieval")

	// Perform hierarchical retrieval using the ORIGINAL question, not the augmented input
	// The augmented input contains frontend context which pollutes the semantic search
	retrievedContext, err := s.ragStore.HierarchicalRetrieval(ctx, question)
	if err != nil {
		slog.WarnContext(ctx, "RAG retrieval failed", "error", err)
		handler.HandleToolError(ctx, err)
		handler.HandleText(ctx, "I encountered an issue retrieving documentation. Please try rephrasing your question.")
		handler.HandleLLMGenerateContentEnd(ctx, &llms.ContentResponse{})
		if ragSpan != nil {
			ragSpan.SetStatus(codes.Error, err.Error())
		}
		s.emitRunFinished(ctx, handler, threadID, runID)
		return "", nil
	}

	slog.InfoContext(ctx, "RAG retrieval successful", "context_length", len(retrievedContext), "context_preview", func() string {
		if len(retrievedContext) > 500 {
			return retrievedContext[:500] + "..."
		}
		return retrievedContext
	}())

	handler.HandleToolEnd(ctx, retrievedContext)

	// Create RAG-augmented prompt with specific instructions
	ragPrompt := fmt.Sprintf(`%s

## RETRIEVED DOCUMENTATION CONTEXT
%s

## INSTRUCTIONS FOR ANSWERING
You have retrieved relevant documentation from Trento's official documentation above. This retrieved content IS your primary source of information. Your task is to:

1. **ALWAYS USE RETRIEVED CONTENT FIRST**: Base your answer primarily on the documentation provided above. Do not rely on general knowledge when specific documentation is available.

2. **EXTRACT STEP-BY-STEP INSTRUCTIONS**: When users ask for installation, configuration, or procedural guidance, extract and present the complete step-by-step instructions from the retrieved documentation. Format them as clear, numbered lists with the exact commands and details from the documentation.

3. **BE COMPREHENSIVE AND SPECIFIC**: Provide complete information from the retrieved context. Include all relevant details, commands, prerequisites, and warnings. Do not give brief answers that just reference external links - instead, quote or paraphrase the actual content.

4. **CITE SOURCES PROPERLY**: Reference the source document name (e.g., "According to the Installation Guide...") and include the "Read more" links when appropriate, but don't use them as a substitute for providing the actual information.

5. **ONLY FALLBACK IF TRULY MISSING**: Only if the retrieved documentation genuinely does not contain any relevant information about the user's question should you suggest external resources. The documentation above should contain the complete answer.

IMPORTANT: If the retrieved context contains installation steps, configuration procedures, or other detailed instructions, you MUST extract and present them directly in your answer. Do not apologize or say the information is not available when it clearly is in the retrieved context.

## USER QUESTION
%s

## YOUR ANSWER
`, s.systemPrompt, retrievedContext, input)

	conv := chains.NewConversation(s.llm, s.memory)
	slog.DebugContext(ctx, "agent: generating RAG response", "threadID", threadID, "runID", runID)
	// Manually trigger LLM callbacks
	handler.llmSystemPrompt = s.systemPrompt
	handler.HandleLLMStart(ctx, []string{ragPrompt})
	output, err := chains.Run(ctx, conv, ragPrompt, chains.WithStreamingFunc(func(ctx context.Context, chunk []byte) error {
		handler.HandleStreamingFunc(ctx, chunk)
		return nil
	}))
	if err != nil {
		slog.WarnContext(ctx, "RAG response error", "error", err)
		handler.HandleLLMError(ctx, err)
		if ragSpan != nil {
			ragSpan.SetStatus(codes.Error, err.Error())
		}
		return "", s.emitRunError(ctx, handler, runID, err)
	}
	slog.DebugContext(ctx, "agent: RAG response completed", "threadID", threadID, "runID", runID)

	// Set output on span
	if ragSpan != nil {
		ragSpan.SetAttributes(
			attribute.String("output.value", truncateSpanAttr(output)),
			attribute.String("output.mime_type", "text/plain"),
		)
		ragSpan.SetStatus(codes.Ok, "rag completed")
	}

	handler.llmOutput = output
	handler.HandleLLMGenerateContentEnd(ctx, &llms.ContentResponse{})
	return output, s.emitRunFinished(ctx, handler, threadID, runID)
}

// resetTools closes any existing MCP client and clears cached tools. This allows
// reinitialization on the next call to ensureTools (useful when the server terminates
// sessions and tools become invalid).
func (s *AgentService) resetTools() {
	if s.mcpClient != nil {
		slog.Debug("resetTools: closing existing MCP client")
		_ = s.mcpClient.Close()
	}
	s.mcpClient = nil
	s.tools = nil
	slog.Info("resetTools: MCP client and tools cleared; will be reinitialized on next call")
}

// Close releases underlying resources.
func (s *AgentService) Close() error {
	if s.mcpClient != nil {
		s.mcpClient.Close()
	}
	if s.ragStore != nil {
		s.ragStore.Close()
	}
	return nil
}
