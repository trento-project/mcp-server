// Copyright 2025 SUSE LLC
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
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

// authContextFuncNoOauth is a context function for the StreamableHTTPServer that
// uses hardcoded credentials to get a token for the trento API
func authContextFuncNoOauth(ctx context.Context, r *http.Request, validateURL, trentoUrl, username, password string) context.Context {
	handleTrentoAuth(trentoUrl, username, password)
	return ctx
}

// authContextFunc is a context function for the StreamableHTTPServer that
// validates the Authorization header and injects the Bearer token into the environment.
func authContextFunc(ctx context.Context, r *http.Request, validateURL, trentoUrl, username, password string) context.Context {
	authHeader := r.Header.Get("Authorization")
	const prefix = "Bearer "
	if len(authHeader) > len(prefix) && authHeader[:len(prefix)] == prefix {
		token := authHeader[len(prefix):]
		if validateAuth0JWT(token, validateURL) {
			// Token is valid, proceed with current logic (hardcoded creds for Trento API)
			handleTrentoAuth(trentoUrl, username, password)
			return ctx
		}
		// If token is invalid, do not set credentials
		return ctx
	}
	// No Authorization header or not Bearer: do not set credentials
	return ctx
}

// validateAuth0JWT validates a JWT token against the Auth0 userinfo endpoint.
func validateAuth0JWT(tokenString, validateURL string) bool {
	userinfoURL := validateURL
	req, err := http.NewRequest("GET", userinfoURL, nil)
	if err != nil {
		return false
	}
	req.Header.Set("Authorization", "Bearer "+tokenString)

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	return resp.StatusCode == http.StatusOK
}

// handleTrentoAuth handles the Trento API authentication with token management
func handleTrentoAuth(trentoUrl, username, password string) {
	tokenMutex.Lock()
	defer tokenMutex.Unlock()
	now := time.Now()
	if cachedAccessToken == "" || now.After(tokenExpiry) {
		// If we have a refresh token and token expired, try to refresh
		if cachedRefreshToken != "" && now.After(tokenExpiry) {
			body, _ := json.Marshal(map[string]string{
				"refresh_token": cachedRefreshToken,
			})
			resp, err := http.Post(
				trentoUrl+"/api/session/refresh",
				"application/json",
				bytes.NewBuffer(body),
			)
			if err == nil && resp.StatusCode == http.StatusOK {
				defer resp.Body.Close()
				respBody, _ := io.ReadAll(resp.Body)
				var result map[string]interface{}
				if err := json.Unmarshal(respBody, &result); err == nil {
					if token, ok := result["access_token"].(string); ok && token != "" {
						cachedAccessToken = token
						os.Setenv("BEARER_TOKEN", token)
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
			performInitialLogin(trentoUrl, username, password)
		}
	} else {
		// Token is still valid
		os.Setenv("BEARER_TOKEN", cachedAccessToken)
	}
}

// performInitialLogin performs the initial login to Trento API with hardcoded credentials
func performInitialLogin(trentoUrl, username, password string) {
	body, _ := json.Marshal(map[string]string{
		"username": username,
		"password": password,
	})
	resp, err := http.Post(
		trentoUrl+"/api/session",
		"application/json",
		bytes.NewBuffer(body),
	)
	if err == nil && resp.StatusCode == http.StatusOK {
		defer resp.Body.Close()
		respBody, _ := io.ReadAll(resp.Body)
		var result map[string]interface{}
		if err := json.Unmarshal(respBody, &result); err == nil {
			if token, ok := result["access_token"].(string); ok && token != "" {
				cachedAccessToken = token
				os.Setenv("BEARER_TOKEN", token)
			}
			if refresh, ok := result["refresh_token"].(string); ok && refresh != "" {
				cachedRefreshToken = refresh
			}
			if expiresIn, ok := result["expires_in"].(float64); ok {
				tokenExpiry = time.Now().Add(time.Duration(expiresIn) * time.Second)
			}
		}
	}
}
