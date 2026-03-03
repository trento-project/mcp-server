// Copyright 2025 SUSE LLC
// SPDX-License-Identifier: Apache-2.0

package rag

import (
	"context"
	"fmt"

	"github.com/tmc/langchaingo/embeddings"
	"github.com/tmc/langchaingo/llms/googleai"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
)

// GeminiEmbedder wraps the Gemini API for creating embeddings
type GeminiEmbedder struct {
	embedder *embeddings.EmbedderImpl
	tracer   trace.Tracer
}

// NewGeminiEmbedder creates a new Gemini-based embedder
func NewGeminiEmbedder(ctx context.Context, apiKey string) (*GeminiEmbedder, error) {
	return NewGeminiEmbedderWithTracer(ctx, apiKey, nil)
}

// NewGeminiEmbedderWithTracer creates a new Gemini-based embedder with optional OpenTelemetry tracer
func NewGeminiEmbedderWithTracer(ctx context.Context, apiKey string, tracer trace.Tracer) (*GeminiEmbedder, error) {
	llm, err := googleai.New(
		ctx,
		googleai.WithAPIKey(apiKey),
		googleai.WithDefaultEmbeddingModel("gemini-embedding-001"),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create Gemini client: %w", err)
	}

	embedder, err := embeddings.NewEmbedder(llm)
	if err != nil {
		return nil, fmt.Errorf("failed to create embedder: %w", err)
	}

	return &GeminiEmbedder{
		embedder: embedder,
		tracer:   tracer,
	}, nil
}

// EmbedDocuments creates embeddings for multiple documents
func (g *GeminiEmbedder) EmbedDocuments(ctx context.Context, texts []string) ([][]float32, error) {
	if g.tracer != nil {
		var span trace.Span
		ctx, span = g.tracer.Start(ctx, "embedding.create", trace.WithAttributes(
			attribute.String("openinference.span.kind", "EMBEDDING"),
			attribute.String("embedding.model_name", "gemini-embedding-001"),
			attribute.Int("embedding.text_count", len(texts)),
		))
		defer span.End()
	}
	return g.embedder.EmbedDocuments(ctx, texts)
}

// EmbedQuery creates an embedding for a single query
func (g *GeminiEmbedder) EmbedQuery(ctx context.Context, text string) ([]float32, error) {
	if g.tracer != nil {
		var span trace.Span
		ctx, span = g.tracer.Start(ctx, "embedding.query", trace.WithAttributes(
			attribute.String("openinference.span.kind", "EMBEDDING"),
			attribute.String("embedding.model_name", "gemini-embedding-001"),
			attribute.String("embedding.text", truncateEmbedText(text, 200)),
		))
		defer span.End()
	}
	return g.embedder.EmbedQuery(ctx, text)
}

func truncateEmbedText(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}
