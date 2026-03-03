// Copyright 2025 SUSE LLC
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"io"
	"log"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	"github.com/tmc/langchaingo/schema"
	"github.com/tmc/langchaingo/textsplitter"
	"github.com/trento-project/mcp-server/internal/rag"
)

const (
	defaultPgURL     = "postgres://postgres:postgres@localhost:5434/trento_rag?sslmode=disable"
	defaultChunkSize = 2000
	defaultOverlap   = 400
)

func main() {
	var (
		docsDir   string
		pgURL     string
		apiKey    string
		chunkSize int
		overlap   int
	)

	flag.StringVar(&docsDir, "docs", "", "Path to directory containing markdown documentation files (required)")
	flag.StringVar(&pgURL, "pg-url", defaultPgURL, "PostgreSQL connection URL")
	flag.StringVar(&apiKey, "api-key", "", "Gemini API key (or set GEMINI_API_KEY env var)")
	flag.IntVar(&chunkSize, "chunk-size", defaultChunkSize, "Size of text chunks for splitting")
	flag.IntVar(&overlap, "overlap", defaultOverlap, "Overlap between chunks")
	flag.Parse()

	if docsDir == "" {
		log.Fatal("--docs flag is required")
	}

	// Get API key from flag or environment
	if apiKey == "" {
		apiKey = os.Getenv("GEMINI_API_KEY")
	}
	if apiKey == "" {
		log.Fatal("Gemini API key required: use --api-key flag or GEMINI_API_KEY environment variable")
	}

	ctx := context.Background()

	// Setup logging
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	})))

	// Initialize embedder
	slog.Info("initializing Gemini embedder")
	embedder, err := rag.NewGeminiEmbedder(ctx, apiKey)
	if err != nil {
		log.Fatalf("failed to create embedder: %v", err)
	}

	// Initialize RAG store
	slog.Info("connecting to pgvector", "url", maskPassword(pgURL))
	store, err := rag.NewRAGStore(ctx, pgURL, embedder)
	if err != nil {
		log.Fatalf("failed to create RAG store: %v", err)
	}
	defer store.Close()

	// Process documentation files
	slog.Info("processing documentation", "dir", docsDir)
	docs, err := processDocumentationDir(ctx, docsDir, chunkSize, overlap)
	if err != nil {
		log.Fatalf("failed to process documentation: %v", err)
	}

	slog.Info("total documents to ingest", "count", len(docs))

	// Batch ingestion to avoid overwhelming the API
	batchSize := 10
	for i := 0; i < len(docs); i += batchSize {
		end := i + batchSize
		if end > len(docs) {
			end = len(docs)
		}

		batch := docs[i:end]
		slog.Info("ingesting batch", "batch", i/batchSize+1, "docs", len(batch))

		ids, err := store.AddDocuments(ctx, batch)
		if err != nil {
			log.Fatalf("failed to add documents: %v", err)
		}

		slog.Info("batch ingested", "ids", len(ids))
	}

	slog.Info("ingestion complete", "total_docs", len(docs))
}

// processDocumentationDir recursively processes all markdown files in a directory
func processDocumentationDir(ctx context.Context, dir string, chunkSize, overlap int) ([]schema.Document, error) {
	var allDocs []schema.Document

	// Create text splitter
	splitter := textsplitter.NewRecursiveCharacter(
		textsplitter.WithChunkSize(chunkSize),
		textsplitter.WithChunkOverlap(overlap),
	)

	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		// Only process markdown files
		if info.IsDir() || !isMarkdownFile(path) {
			return nil
		}

		slog.Info("processing file", "path", path)

		content, err := readFile(path)
		if err != nil {
			slog.Warn("failed to read file", "path", path, "error", err)
			return nil // Skip this file
		}

		// Extract title from first heading or filename
		title := extractTitle(content, path)

		// Split into chunks
		chunks, err := splitter.SplitText(content)
		if err != nil {
			slog.Warn("failed to split text", "path", path, "error", err)
			return nil
		}

		// Create documents for each chunk
		for i, chunk := range chunks {
			doc := schema.Document{
				PageContent: chunk,
				Metadata: map[string]any{
					"source":       path,
					"title":        title,
					"chunk":        i,
					"total_chunks": len(chunks),
				},
			}
			allDocs = append(allDocs, doc)
		}

		return nil
	})

	if err != nil {
		return nil, fmt.Errorf("failed to walk directory: %w", err)
	}

	return allDocs, nil
}

// isMarkdownFile checks if a file has a markdown extension
func isMarkdownFile(path string) bool {
	ext := strings.ToLower(filepath.Ext(path))
	return ext == ".md" || ext == ".markdown" || ext == ".adoc" || ext == ".asciidoc"
}

// readFile reads the entire contents of a file
func readFile(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()

	var builder strings.Builder
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		builder.WriteString(scanner.Text())
		builder.WriteString("\n")
	}

	if err := scanner.Err(); err != nil && err != io.EOF {
		return "", err
	}

	return builder.String(), nil
}

// extractTitle extracts the title from the content or uses the filename
func extractTitle(content, path string) string {
	lines := strings.Split(content, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		// Markdown heading
		if strings.HasPrefix(line, "# ") {
			return strings.TrimPrefix(line, "# ")
		}
		// AsciiDoc heading
		if strings.HasPrefix(line, "= ") {
			return strings.TrimPrefix(line, "= ")
		}
	}

	// Fallback to filename
	return strings.TrimSuffix(filepath.Base(path), filepath.Ext(path))
}

// maskPassword masks the password in a connection URL for logging
func maskPassword(url string) string {
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
