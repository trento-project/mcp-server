// Copyright 2025 SUSE LLC
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"os"
	"sync"
	"time"
)

var (
	cachedAccessToken  string
	cachedRefreshToken string
	tokenExpiry        time.Time
	tokenMutex         sync.Mutex
)

// authContextFuncNoOauth is a context function for the server that
// uses hardcoded credentials to get a token for the trento API.
func authContextFuncNoOauth(ctx context.Context, _ *http.Request, _, trentoUrl, username, password string) context.Context {
	err := handleTrentoAuth(ctx, trentoUrl, username, password)
	if err != nil {
		slog.ErrorContext(ctx, "failed to handle Trento auth", "error", err)
	}

	return ctx
}

// authContextFunc is a context function for the server that
// validates the Authorization header and injects the Bearer token into the environment.
func authContextFunc(ctx context.Context, r *http.Request, validateURL, trentoUrl, username, password string) context.Context {
	authHeader := r.Header.Get("Authorization")

	const prefix = "Bearer "

	if len(authHeader) > len(prefix) && authHeader[:len(prefix)] == prefix {
		token := authHeader[len(prefix):]
		if validateAuth0JWT(ctx, token, validateURL) {
			// Token is valid, proceed with current logic (hardcoded creds for Trento API)
			err := handleTrentoAuth(ctx, trentoUrl, username, password)
			if err != nil {
				slog.ErrorContext(ctx, "failed to handle Trento auth", "error", err)

				return ctx
			}

			return ctx
		}
		// If token is invalid, do not set credentials
		return ctx
	}
	// No Authorization header or not Bearer: do not set credentials
	return ctx
}

// validateAuth0JWT validates a JWT token against the Auth0 userinfo endpoint.
func validateAuth0JWT(ctx context.Context, tokenString, validateURL string) bool {
	userinfoURL := validateURL

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, userinfoURL, nil)
	if err != nil {
		return false
	}

	client := &http.Client{}

	req.Header.Set("Authorization", "Bearer "+tokenString)

	resp, err := client.Do(req)
	if err != nil {
		return false
	}

	defer resp.Body.Close()

	return resp.StatusCode == http.StatusOK
}

// handleTrentoAuth handles the Trento API authentication with token management.
func handleTrentoAuth(ctx context.Context, trentoUrl, username, password string) error {
	tokenMutex.Lock()
	defer tokenMutex.Unlock()

	var err error

	now := time.Now()
	if cachedAccessToken == "" || now.After(tokenExpiry) {
		// If we have a refresh token and token expired, try to refresh
		if cachedRefreshToken != "" && now.After(tokenExpiry) {
			body, err := json.Marshal(map[string]string{
				"refresh_token": cachedRefreshToken,
			})
			if err != nil {
				return err
			}

			req, err := http.NewRequestWithContext(ctx, http.MethodPost, trentoUrl+"/api/session", bytes.NewBuffer(body))
			if err != nil {
				return err
			}

			req.Header.Set("Content-Type", "application/json")

			client := &http.Client{}

			resp, err := client.Do(req)
			if err == nil && resp.StatusCode == http.StatusOK {
				defer resp.Body.Close()

				respBody, _ := io.ReadAll(resp.Body)

				var result map[string]any

				err := json.Unmarshal(respBody, &result)
				if err == nil {
					if token, ok := result["access_token"].(string); ok && token != "" {
						cachedAccessToken = token

						err = os.Setenv("BEARER_TOKEN", token)
						//nolint:revive
						if err != nil {
							return err
						}
					}

					if refresh, ok := result["refresh_token"].(string); ok && refresh != "" {
						cachedRefreshToken = refresh
					}

					if expiresIn, ok := result["expires_in"].(float64); ok {
						tokenExpiry = now.Add(time.Duration(expiresIn) * time.Second)
					}
				}
			} else {
				// If refresh fails, clear tokens and fall back to login
				cachedAccessToken = ""
				cachedRefreshToken = ""
				tokenExpiry = time.Time{}
			}
		}

		if cachedAccessToken == "" {
			// No refresh token or refresh failed, do initial login
			err = performInitialLogin(ctx, trentoUrl, username, password)
			if err != nil {
				return err
			}
		}
	} else {
		// Token is still valid
		err = os.Setenv("BEARER_TOKEN", cachedAccessToken)
		if err != nil {
			return err
		}
	}

	return err
}

// performInitialLogin performs the initial login to Trento API with hardcoded credentials.
func performInitialLogin(ctx context.Context, trentoUrl, username, password string) error {
	body, err := json.Marshal(map[string]string{
		"username": username,
		"password": password,
	})
	if err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, trentoUrl+"/api/session", bytes.NewBuffer(body))
	if err != nil {
		return err
	}

	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{}

	resp, err := client.Do(req)
	if err == nil && resp.StatusCode == http.StatusOK {
		defer resp.Body.Close()

		respBody, _ := io.ReadAll(resp.Body)

		var result map[string]any

		err := json.Unmarshal(respBody, &result)
		if err == nil {
			if token, ok := result["access_token"].(string); ok && token != "" {
				cachedAccessToken = token

				err = os.Setenv("BEARER_TOKEN", token)
				if err != nil {
					return err
				}
			}

			if refresh, ok := result["refresh_token"].(string); ok && refresh != "" {
				cachedRefreshToken = refresh
			}

			if expiresIn, ok := result["expires_in"].(float64); ok {
				tokenExpiry = time.Now().Add(time.Duration(expiresIn) * time.Second)
			}
		}
	}

	return err
}
