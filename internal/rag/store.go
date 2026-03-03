// Copyright 2025 SUSE LLC
// SPDX-License-Identifier: Apache-2.0

package rag

import (
	"context"
	"fmt"
	"log/slog"
	"path/filepath"
	"strings"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/tmc/langchaingo/embeddings"
	"github.com/tmc/langchaingo/schema"
	"github.com/tmc/langchaingo/vectorstores"
	"github.com/tmc/langchaingo/vectorstores/pgvector"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
)

const (
	// Hierarchical retrieval parameters
	broadRetrievalNumDocs           = 15
	broadRetrievalScoreThreshold    = 0.4
	detailedRetrievalNumDocs        = 8
	detailedRetrievalScoreThreshold = 0.45
	relevantDocsLimit               = 5

	// Additional context parameters
	additionalBroadDocsLimit = 3

	// Text truncation parameters
	maxTruncateLength = 200
)

// RAGStore manages document storage and retrieval using pgvector
type RAGStore struct {
	store    pgvector.Store
	pool     *pgxpool.Pool
	embedder embeddings.Embedder
	tracer   trace.Tracer
}

// NewRAGStore creates a new RAG store connected to pgvector
func NewRAGStore(ctx context.Context, connectionURL string, embedder embeddings.Embedder) (*RAGStore, error) {
	return NewRAGStoreWithTracer(ctx, connectionURL, embedder, nil)
}

// NewRAGStoreWithTracer creates a new RAG store with optional OpenTelemetry tracer
func NewRAGStoreWithTracer(ctx context.Context, connectionURL string, embedder embeddings.Embedder, tracer trace.Tracer) (*RAGStore, error) {
	// Create connection pool
	pool, err := pgxpool.New(ctx, connectionURL)
	if err != nil {
		return nil, fmt.Errorf("failed to create connection pool: %w", err)
	}

	// Test connection
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("failed to connect to database: %w", err)
	}

	// Create pgvector store
	store, err := pgvector.New(
		ctx,
		pgvector.WithConn(pool),
		pgvector.WithEmbedder(embedder),
		pgvector.WithCollectionName("trento_docs"),
		pgvector.WithPreDeleteCollection(false),
	)
	if err != nil {
		pool.Close()
		return nil, fmt.Errorf("failed to create pgvector store: %w", err)
	}

	slog.InfoContext(ctx, "RAG store initialized", "collection", "trento_docs")

	return &RAGStore{
		store:    store,
		pool:     pool,
		embedder: embedder,
		tracer:   tracer,
	}, nil
}

// AddDocuments adds documents to the vector store
func (r *RAGStore) AddDocuments(ctx context.Context, docs []schema.Document) ([]string, error) {
	ids, err := r.store.AddDocuments(ctx, docs)
	if err != nil {
		return nil, fmt.Errorf("failed to add documents: %w", err)
	}
	slog.InfoContext(ctx, "documents added to RAG store", "count", len(ids))
	return ids, nil
}

// SimilaritySearch performs a similarity search and returns relevant documents
func (r *RAGStore) SimilaritySearch(ctx context.Context, query string, numDocs int, scoreThreshold float32) ([]schema.Document, error) {
	docs, err := r.store.SimilaritySearch(
		ctx,
		query,
		numDocs,
		vectorstores.WithScoreThreshold(scoreThreshold),
	)
	if err != nil {
		return nil, fmt.Errorf("similarity search failed: %w", err)
	}

	slog.InfoContext(ctx, "similarity search completed", "query", query, "results", len(docs))
	return docs, nil
}

// HierarchicalRetrieval performs multi-level retrieval:
// 1. First retrieves broad context chunks
// 2. Then re-ranks and retrieves specific details
func (r *RAGStore) HierarchicalRetrieval(ctx context.Context, query string) (string, error) {
	// Create RETRIEVER span
	if r.tracer != nil {
		var span trace.Span
		ctx, span = r.tracer.Start(ctx, "rag.retrieval", trace.WithAttributes(
			attribute.String("openinference.span.kind", "RETRIEVER"),
			attribute.String("input.value", query),
			attribute.String("input.mime_type", "text/plain"),
		))
		defer func() {
			if span != nil {
				span.End()
			}
		}()
	}

	// Step 1: Broad retrieval - get general context
	slog.DebugContext(ctx, "hierarchical retrieval: broad search", "query", query)
	broadDocs, err := r.SimilaritySearch(ctx, query, broadRetrievalNumDocs, broadRetrievalScoreThreshold)
	if err != nil {
		return "", err
	}

	if len(broadDocs) == 0 {
		return "No relevant documentation found.", nil
	}

	// Step 2: Extract key topics from broad results
	// For now, just use the broad results, but this could be enhanced
	// with a re-ranking step or query decomposition

	// Step 3: Detailed retrieval - get specific information with higher relevance
	slog.DebugContext(ctx, "hierarchical retrieval: detailed search", "broad_results", len(broadDocs))
	detailedDocs, err := r.SimilaritySearch(ctx, query, detailedRetrievalNumDocs, detailedRetrievalScoreThreshold)
	if err != nil {
		return "", err
	}

	// Combine and format results
	result := r.formatRetrievalResults(broadDocs, detailedDocs, relevantDocsLimit)

	// Set retrieval.documents attributes if we have a span
	if r.tracer != nil {
		// Get the current span from context
		span := trace.SpanFromContext(ctx)
		if span.IsRecording() {
			// Set document count and sample content
			span.SetAttributes(
				attribute.Int("retrieval.document_count", len(detailedDocs)),
				attribute.String("output.value", result[:min(len(result), 500)]),
				attribute.String("output.mime_type", "text/plain"),
			)
			// Set flattened document attributes for top results
			for i, doc := range detailedDocs {
				if i >= 5 { // Limit to top 5 to avoid too many attributes
					break
				}
				prefix := fmt.Sprintf("retrieval.documents.%d", i)
				span.SetAttributes(
					attribute.String(prefix+".document.content", truncateDocContent(doc.PageContent, 200)),
					attribute.Float64(prefix+".document.score", float64(doc.Score)),
				)
				if id, ok := doc.Metadata["id"].(string); ok {
					span.SetAttributes(attribute.String(prefix+".document.id", id))
				}
			}
		}
	}

	return result, nil
}

func truncateDocContent(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// formatRetrievalResults formats the retrieved documents into a coherent context
func (r *RAGStore) formatRetrievalResults(broadDocs, detailedDocs []schema.Document, relevantDocs int) string {
	context := "## Retrieved Documentation Context\n\n"

	// Track URLs that have already been added to prevent duplicates
	addedURLs := make(map[string]bool)

	if len(detailedDocs) > 0 {
		context += "### Most Relevant Information:\n\n"
		for i, doc := range detailedDocs {
			if i >= relevantDocs { // Limit detailed results to top ones
				break
			}
			context += fmt.Sprintf("**Document %d** (relevance: %.2f):\n%s\n\n", i+1, doc.Score, doc.PageContent)

			// Add "Read more" link if we can generate a URL and it hasn't been added yet
			if source, ok := doc.Metadata["source"].(string); ok {
				if url := r.generateDocumentationURL(source); url != "" && !addedURLs[url] {
					context += fmt.Sprintf("*Read more: %s*\n", url)
					addedURLs[url] = true
				}
			}
			context += "\n\n"
		}
	}

	if len(broadDocs) > len(detailedDocs) {
		context += "### Additional Context:\n\n"
		// Add unique broad context not in detailed
		seen := make(map[string]bool)
		for _, d := range detailedDocs {
			seen[d.PageContent] = true
		}

		count := 0
		for _, doc := range broadDocs {
			if !seen[doc.PageContent] && count < additionalBroadDocsLimit {
				context += fmt.Sprintf("- %s\n", truncate(doc.PageContent))
				// Add "Read more" link for broad results too, if not already added
				if source, ok := doc.Metadata["source"].(string); ok {
					if url := r.generateDocumentationURL(source); url != "" && !addedURLs[url] {
						context += fmt.Sprintf("  *Read more: %s*\n", url)
						addedURLs[url] = true
					}
				}
				count++
			}
		}
		context += "\n"
	}

	return context
}

// generateDocumentationURL converts a file path to a SUSE documentation URL
func (r *RAGStore) generateDocumentationURL(filePath string) string {
	// Handle Windows-style paths by converting backslashes to forward slashes
	filePath = strings.ReplaceAll(filePath, "\\", "/")

	// Check if this is a trento documentation file
	if strings.Contains(filePath, "/trento_docs/") || strings.Contains(filePath, "\\trento_docs\\") {
		// Extract filename without extension
		base := filepath.Base(filePath)
		if strings.HasSuffix(base, ".md") {
			filename := strings.TrimSuffix(base, ".md")
			return fmt.Sprintf("https://documentation.suse.com/sles-sap/trento/html/SLES-SAP-trento/%s.html", filename)
		}
	}

	// Check if this is a SLES-SAP guide file
	if strings.Contains(filePath, "/sles-sap_docs/") || strings.Contains(filePath, "\\sles-sap_docs\\") {
		// Extract filename without extension
		base := filepath.Base(filePath)
		if strings.HasSuffix(base, ".md") {
			filename := strings.TrimSuffix(base, ".md")
			return fmt.Sprintf("https://documentation.suse.com/sles-sap/15-SP7/single-html/SLES-SAP-guide/%s.html", filename)
		}
	}

	// If no pattern matches, return empty string
	return ""
}
func truncate(s string) string {
	if len(s) <= maxTruncateLength {
		return s
	}
	return s[:maxTruncateLength] + "..."
}

// Close closes the database connection pool
func (r *RAGStore) Close() {
	if r.pool != nil {
		r.pool.Close()
	}
}
