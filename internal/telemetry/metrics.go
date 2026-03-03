package telemetry

import (
	"context"
	"log/slog"

	"go.opentelemetry.io/otel/metric"
)

// Metrics holds all the instrumented metrics for the agent.
type Metrics struct {
	// Agent execution metrics
	AgentExecutionLatency metric.Float64Histogram
	AgentSuccessCount     metric.Int64Counter
	AgentErrorCount       metric.Int64Counter

	// Tool metrics
	ToolCallLatency metric.Float64Histogram
	ToolCallCount   metric.Int64Counter
	ToolErrorCount  metric.Int64Counter

	// LLM metrics
	LLMCallLatency  metric.Float64Histogram
	LLMInputTokens  metric.Int64Counter
	LLMOutputTokens metric.Int64Counter

	// Decision routing metrics
	DecisionDirectAnswer metric.Int64Counter
	DecisionMCPTool      metric.Int64Counter
	DecisionFallback     metric.Int64Counter
}

// InitializeMetrics creates and returns all metrics from the given meter.
func InitializeMetrics(ctx context.Context, meter metric.Meter) (*Metrics, error) {
	slog.DebugContext(ctx, "initializing metrics")

	// Agent execution latency (in milliseconds)
	agentLatency, err := meter.Float64Histogram(
		"agent.execution.latency",
		metric.WithDescription("Agent execution latency in milliseconds"),
		metric.WithUnit("ms"),
	)
	if err != nil {
		return nil, err
	}

	// Agent success count
	agentSuccess, err := meter.Int64Counter(
		"agent.execution.success",
		metric.WithDescription("Number of successful agent executions"),
	)
	if err != nil {
		return nil, err
	}

	// Agent error count
	agentError, err := meter.Int64Counter(
		"agent.execution.error",
		metric.WithDescription("Number of failed agent executions"),
	)
	if err != nil {
		return nil, err
	}

	// Tool call latency (in milliseconds)
	toolLatency, err := meter.Float64Histogram(
		"tool.call.latency",
		metric.WithDescription("Tool execution latency in milliseconds"),
		metric.WithUnit("ms"),
	)
	if err != nil {
		return nil, err
	}

	// Tool call count
	toolCount, err := meter.Int64Counter(
		"tool.call.count",
		metric.WithDescription("Number of tool calls"),
	)
	if err != nil {
		return nil, err
	}

	// Tool error count
	toolError, err := meter.Int64Counter(
		"tool.call.error",
		metric.WithDescription("Number of failed tool calls"),
	)
	if err != nil {
		return nil, err
	}

	// LLM call latency (in milliseconds)
	llmLatency, err := meter.Float64Histogram(
		"llm.call.latency",
		metric.WithDescription("LLM API call latency in milliseconds"),
		metric.WithUnit("ms"),
	)
	if err != nil {
		return nil, err
	}

	// LLM input tokens
	llmInputTokens, err := meter.Int64Counter(
		"llm.tokens.input",
		metric.WithDescription("Total LLM input tokens consumed"),
	)
	if err != nil {
		return nil, err
	}

	// LLM output tokens
	llmOutputTokens, err := meter.Int64Counter(
		"llm.tokens.output",
		metric.WithDescription("Total LLM output tokens generated"),
	)
	if err != nil {
		return nil, err
	}

	// Decision: direct answer
	decisionDirectAnswer, err := meter.Int64Counter(
		"agent.decision.direct_answer",
		metric.WithDescription("Number of times agent chose direct answer route"),
	)
	if err != nil {
		return nil, err
	}

	// Decision: MCP tool
	decisionMCPTool, err := meter.Int64Counter(
		"agent.decision.mcp_tool",
		metric.WithDescription("Number of times agent chose MCP tool route"),
	)
	if err != nil {
		return nil, err
	}

	// Decision: fallback
	decisionFallback, err := meter.Int64Counter(
		"agent.decision.fallback",
		metric.WithDescription("Number of times agent fell back due to unavailable tools"),
	)
	if err != nil {
		return nil, err
	}

	slog.DebugContext(ctx, "metrics initialized successfully")
	return &Metrics{
		AgentExecutionLatency: agentLatency,
		AgentSuccessCount:     agentSuccess,
		AgentErrorCount:       agentError,
		ToolCallLatency:       toolLatency,
		ToolCallCount:         toolCount,
		ToolErrorCount:        toolError,
		LLMCallLatency:        llmLatency,
		LLMInputTokens:        llmInputTokens,
		LLMOutputTokens:       llmOutputTokens,
		DecisionDirectAnswer:  decisionDirectAnswer,
		DecisionMCPTool:       decisionMCPTool,
		DecisionFallback:      decisionFallback,
	}, nil
}
