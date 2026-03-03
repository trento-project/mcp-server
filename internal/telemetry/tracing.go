package telemetry

import (
	"context"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
)

// Tracer wraps the OTEL tracer for agent instrumentation.
type Tracer struct {
	tracer trace.Tracer
}

// NewTracer creates a new tracer instance.
func NewTracer(tp trace.TracerProvider) *Tracer {
	return &Tracer{
		tracer: tp.Tracer("trento-agent"),
	}
}

// StartAgentRun creates a new span for an agent execution.
func (t *Tracer) StartAgentRun(ctx context.Context, question string, runID string) (context.Context, trace.Span) {
	opts := []trace.SpanStartOption{
		trace.WithSpanKind(trace.SpanKindServer),
		trace.WithAttributes(
			attribute.String("agent.run_id", runID),
			attribute.String("agent.question", question),
			attribute.String("agent.span_kind", "agent_run"),
		),
	}

	return t.tracer.Start(ctx, "agent.execute", opts...)
}

// StartToolCall creates a new span for a tool execution.
func (t *Tracer) StartToolCall(ctx context.Context, toolName string, input string) (context.Context, trace.Span) {
	opts := []trace.SpanStartOption{
		trace.WithSpanKind(trace.SpanKindInternal),
		trace.WithAttributes(
			attribute.String("tool.name", toolName),
			attribute.String("tool.input", input),
			attribute.String("span_kind", "tool_call"),
		),
	}

	return t.tracer.Start(ctx, "tool.call", opts...)
}

// StartLLMCall creates a new span for an LLM API call.
func (t *Tracer) StartLLMCall(ctx context.Context, model string) (context.Context, trace.Span) {
	opts := []trace.SpanStartOption{
		trace.WithSpanKind(trace.SpanKindClient),
		trace.WithAttributes(
			attribute.String("llm.model", model),
			attribute.String("span_kind", "llm_call"),
		),
	}

	return t.tracer.Start(ctx, "llm.call", opts...)
}

// StartPlanningPhase creates a span for the agent planning/routing.
func (t *Tracer) StartPlanningPhase(ctx context.Context) (context.Context, trace.Span) {
	opts := []trace.SpanStartOption{
		trace.WithSpanKind(trace.SpanKindInternal),
	}
	return t.tracer.Start(ctx, "agent.planning", opts...)
}

// RecordToolResult records the result of a tool call on the active span.
func RecordToolResult(span trace.Span, output string, err error) {
	if err != nil {
		span.AddEvent("tool.error", trace.WithAttributes(
			attribute.String("error.message", err.Error()),
		))
		span.SetStatus(codes.Error, err.Error())
	} else {
		span.AddEvent("tool.success")
	}
}

// RecordLLMTokens records token usage on the active span.
func RecordLLMTokens(span trace.Span, inputTokens, outputTokens int64) {
	span.AddEvent("llm.tokens", trace.WithAttributes(
		attribute.Int64("llm.input_tokens", inputTokens),
		attribute.Int64("llm.output_tokens", outputTokens),
	))
}

// GetDefaultTracer returns the global default tracer.
func GetDefaultTracer() trace.Tracer {
	return otel.Tracer("trento-agent")
}
