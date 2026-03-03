package agui

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"

	"time"

	"github.com/ag-ui-protocol/ag-ui/sdks/community/go/pkg/core/events"
	"github.com/ag-ui-protocol/ag-ui/sdks/community/go/pkg/encoding/sse"
	"github.com/trento-project/mcp-server/internal/agent"
	"golang.org/x/sync/errgroup"
)

// SSEServer is an AG-UI protocol compliant server using Server-Sent Events (SSE)
// instead of WebSockets for streaming agent responses.
type SSEServer struct {
	service *agent.AgentService
	addr    string
}

// NewSSEServer creates a new AG-UI SSE server bound to the provided address.
func NewSSEServer(s *agent.AgentService, addr string) *SSEServer {
	return &SSEServer{service: s, addr: addr}
}

// AgenticInput represents the input payload for running an agent via the /agentic endpoint
type AgenticInput struct {
	ThreadID       string           `json:"threadId,omitempty"`
	RunID          string           `json:"runId,omitempty"`
	MessageID      string           `json:"messageId,omitempty"`
	State          any              `json:"state,omitempty"`
	Messages       []map[string]any `json:"messages,omitempty"`
	Tools          []any            `json:"tools,omitempty"`
	Context        []any            `json:"context,omitempty"`
	Query          string           `json:"query,omitempty"` // direct query string
	ForwardedProps any              `json:"forwardedProps,omitempty"`
}

// Run starts the HTTP SSE server and blocks until it returns.
func (s *SSEServer) Run(ctx context.Context) error {
	mux := http.NewServeMux()

	// Minimal info endpoint for external UIs (e.g., CopilotKit expected path)
	mux.HandleFunc("/api/agent/info", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Access-Control-Allow-Origin", "*")
		json.NewEncoder(w).Encode(map[string]any{
			"status":   "ok",
			"provider": "trento-mcp-server",
			"protocol": "ag-ui",
		})
	})

	// Threads search stub endpoint to satisfy external UI discovery
	mux.HandleFunc("/api/agent/threads/search", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Access-Control-Allow-Origin", "*")
		// Return an empty list for now; threads are not persisted
		json.NewEncoder(w).Encode(map[string]any{
			"threads": []any{},
		})
	})

	// Health check endpoint
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	})

	// Info endpoint
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"message":  "AG-UI Trento MCP Server is running!",
			"protocol": "AG-UI Protocol v1.0",
		})
	})

	// SSE agentic endpoint - streaming agent responses using AG-UI protocol
	mux.HandleFunc("/api/agent", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, Cache-Control")

		// Preflight
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}

		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		var input AgenticInput
		if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
			slog.ErrorContext(r.Context(), "failed to parse request body", "error", err)
			http.Error(w, "Invalid request body", http.StatusBadRequest)
			return
		}

		if input.ThreadID == "" {
			input.ThreadID = events.GenerateThreadID()
		}
		if input.RunID == "" {
			input.RunID = events.GenerateRunID()
		}

		query := strings.TrimSpace(input.Query)
		if query == "" && len(input.Messages) > 0 {
			last := input.Messages[len(input.Messages)-1]
			if content, ok := last["content"].(string); ok {
				query = strings.TrimSpace(content)
			}
		}
		if query == "" {
			http.Error(w, "missing query", http.StatusBadRequest)
			return
		}

		// Set SSE response headers (after validation as in example)
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("Connection", "keep-alive")
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Headers", "Cache-Control, Content-Type, Authorization")

		slog.InfoContext(r.Context(), "ag-ui: SSE connection established",
			"threadId", input.ThreadID, "runId", input.RunID)

		// Stream events using SSE
		s.streamAgenticEvents(w, r.Context(), &input, query)
	})

	srv := &http.Server{
		Addr:    s.addr,
		Handler: mux,
	}

	go func() {
		<-ctx.Done()
		srv.Close()
	}()

	slog.InfoContext(ctx, "ag-ui SSE server listening", "addr", s.addr)
	return srv.ListenAndServe()
}

// streamAgenticEvents handles streaming of agent responses as SSE events
func (s *SSEServer) streamAgenticEvents(w http.ResponseWriter, ctx context.Context, input *AgenticInput, query string) {
	// Create SSE writer
	sseWriter := sse.NewSSEWriter().WithLogger(slog.Default())

	// Create event channel for collecting events
	eventChan := make(chan json.RawMessage, 100)
	// Channel will be closed by the producer goroutine when done

	// Use provided message ID if any, otherwise generate
	messageID := input.MessageID
	if messageID == "" {
		messageID = events.GenerateMessageID()
	}

	// Use errgroup for concurrent processing
	g, groupCtx := errgroup.WithContext(ctx)

	// Goroutine 1: Write events to SSE stream
	g.Go(func() error {
		flusher, ok := w.(http.Flusher)
		if !ok {
			return fmt.Errorf("response writer does not support flushing")
		}

		writer := bufio.NewWriter(w)
		defer writer.Flush()

		for {
			select {
			case event, ok := <-eventChan:
				if !ok {
					// Channel closed, we're done
					return nil
				}

				// Write the event as an SSE frame
				if err := sseWriter.WriteBytes(groupCtx, writer, event); err != nil {
					slog.WarnContext(groupCtx, "ag-ui: failed to write SSE event", "error", err)
					return err
				}

				// Flush to ensure the event is sent immediately
				flusher.Flush()

			case <-groupCtx.Done():
				return groupCtx.Err()
			}
		}
	})

	// Goroutine 2: Execute agent and collect events
	g.Go(func() error {
		defer close(eventChan)

		// Set a timeout for agent execution
		execCtx, cancel := context.WithTimeout(groupCtx, 60*time.Second)
		defer cancel()

		// frontendCtx := map[string]any{}
		// if len(input.Context) > 0 {
		// 	frontendCtx["context"] = input.Context
		// }
		// if input.ForwardedProps != nil {
		// 	frontendCtx["forwardedProps"] = input.ForwardedProps
		// }
		// if len(input.Tools) > 0 {
		// 	frontendCtx["tools"] = input.Tools
		// }
		// if len(input.Messages) > 0 {
		// 	frontendCtx["messages"] = input.Messages
		// }

		// Fallback: if no explicit context provided, try to extract from forwarded props, state, or system messages
		// if len(input.Context) == 0 {
		// 	// From forwarded props (camelCase only)
		// 	if input.ForwardedProps != nil {
		// 		if m, ok := input.ForwardedProps.(map[string]any); ok {
		// 			if ctxVal, ok := m["context"]; ok {
		// 				switch t := ctxVal.(type) {
		// 				case []any:
		// 					input.Context = t
		// 				default:
		// 					input.Context = append(input.Context, t)
		// 				}
		// 			}
		// 			if ctxVal, ok := m["model_context"]; ok {
		// 				switch t := ctxVal.(type) {
		// 				case []any:
		// 					input.Context = t
		// 				default:
		// 					input.Context = append(input.Context, t)
		// 				}
		// 			}
		// 		}
		// 		if m, ok := input.State.(map[string]any); ok {
		// 			if ctxVal, ok := m["context"]; ok {
		// 				switch t := ctxVal.(type) {
		// 				case []any:
		// 					input.Context = t
		// 				default:
		// 					input.Context = append(input.Context, t)
		// 				}
		// 			}
		// 		}
		// 	}

		// 	// From system/activity messages or embedded prefixes
		// 	if len(input.Context) == 0 && len(input.Messages) > 0 {
		// 		for _, msg := range input.Messages {
		// 			if role, ok := msg["role"].(string); ok && (role == "system" || role == "activity") {
		// 				if content, ok := msg["content"].(string); ok && strings.TrimSpace(content) != "" {
		// 					input.Context = append(input.Context, map[string]any{"description": "system message", "value": content})
		// 				}
		// 			}
		// 			if content, ok := msg["content"].(string); ok {
		// 				if strings.HasPrefix(content, "Model context:") || strings.HasPrefix(content, "Frontend context:") {
		// 					input.Context = append(input.Context, map[string]any{"description": "parsed from message", "value": content})
		// 				}
		// 			}
		// 		}
		// 	}

		// 	if len(input.Context) > 0 {
		// 		slog.Debug("ag-ui: extracted context from payload", "context_preview", input.Context)
		// 	}
		// }

		// Execute the agent with streaming
		if err := s.service.ExecuteWithStreaming(execCtx, eventChan, input.ThreadID, input.RunID, messageID, query, input.Context, input.Tools); err != nil {
			slog.WarnContext(execCtx, "ag-ui: agent execution error", "error", err)
			// Event has already been written to the channel by ExecuteWithStreaming
		}

		return nil
	})

	// Wait for both goroutines to complete
	if err := g.Wait(); err != nil {
		slog.ErrorContext(ctx, "ag-ui: error streaming events", "error", err)
	}
}
