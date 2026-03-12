package domains

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/apigateway"
	smithy "github.com/aws/smithy-go"
)

// gatewayAPIRetries is the maximum number of retries for AWS API Gateway operations
// when rate-limited (429). With exponential backoff starting at 2s, this provides
// up to 11 attempts with increasing delays, ensuring cleanup completes even under
// aggressive rate limiting.
const gatewayAPIRetries = 10

// swaggerTemplate is the OpenAPI/Swagger 2.0 template for the API Gateway HTTP proxy.
// {{url}} is replaced with the target DoH server URL.
const swaggerTemplate = `{
  "swagger": "2.0",
  "info": {"version": "1.0", "title": "pius-doh-proxy"},
  "basePath": "/",
  "schemes": ["https"],
  "paths": {
    "/": {
      "get": {
        "produces": ["application/json"],
        "parameters": [
          {"name": "X-My-X-Forwarded-For", "in": "header", "required": false, "type": "string"},
          {"name": "X-My-Authorization", "in": "header", "required": false, "type": "string"},
          {"name": "X-My-X-Amzn-Trace-Id", "in": "header", "required": false, "type": "string"}
        ],
        "responses": {"200": {"description": "200 response"}},
        "x-amazon-apigateway-integration": {
          "uri": "{{url}}",
          "type": "http_proxy",
          "httpMethod": "ANY",
          "requestParameters": {
            "integration.request.header.X-Forwarded-For": "method.request.header.X-My-X-Forwarded-For",
            "integration.request.header.Authorization": "method.request.header.X-My-Authorization",
            "integration.request.header.X-Amzn-Trace-Id": "method.request.header.X-My-X-Amzn-Trace-Id"
          },
          "passthroughBehavior": "when_no_match"
        }
      }
    },
    "/{proxy+}": {
      "get": {
        "produces": ["application/json"],
        "parameters": [
          {"name": "proxy", "in": "path", "required": true, "type": "string"},
          {"name": "X-My-X-Forwarded-For", "in": "header", "required": false, "type": "string"},
          {"name": "X-My-Authorization", "in": "header", "required": false, "type": "string"},
          {"name": "X-My-X-Amzn-Trace-Id", "in": "header", "required": false, "type": "string"}
        ],
        "responses": {"200": {"description": "200 response"}},
        "x-amazon-apigateway-integration": {
          "uri": "{{url}}/{proxy}",
          "type": "http_proxy",
          "httpMethod": "ANY",
          "requestParameters": {
            "integration.request.header.X-Forwarded-For": "method.request.header.X-My-X-Forwarded-For",
            "integration.request.header.Authorization": "method.request.header.X-My-Authorization",
            "integration.request.header.X-Amzn-Trace-Id": "method.request.header.X-My-X-Amzn-Trace-Id"
          },
          "passthroughBehavior": "when_no_match"
        }
      }
    }
  }
}`

// defaultGatewayRegions lists AWS regions used for multi-region gateway deployment.
var defaultGatewayRegions = []string{
	"us-east-1",
	"us-east-2",
	"us-west-1",
	"us-west-2",
	"eu-west-1",
	"eu-central-1",
	"ap-northeast-1",
	"ap-southeast-1",
}

// createdGateway tracks a gateway that was deployed for later cleanup.
type createdGateway struct {
	apiID     string
	region    string
	invokeURL string
}

// deployAPIGateways creates AWS API Gateways in multiple regions for each provided DoH server URL.
// Returns the list of gateway endpoints and a cleanup function to delete all created gateways.
//
// NOTE: This function requires AWS credentials in the environment (AWS_ACCESS_KEY_ID,
// AWS_SECRET_ACCESS_KEY, AWS_SESSION_TOKEN or an IAM role). If the AWS SDK is not available
// or credentials are missing, it returns an error.
func deployAPIGateways(ctx context.Context, dohServers []string) ([]DoHEndpoint, func(), error) {
	if len(dohServers) == 0 {
		return nil, func() {}, fmt.Errorf("no DoH servers provided for gateway deployment")
	}

	// Load base config once and verify credentials are available.
	baseCfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		return nil, func() {}, fmt.Errorf("doh-enum: AWS credentials not available for gateway deployment: %w", err)
	}
	creds, err := baseCfg.Credentials.Retrieve(ctx)
	if err != nil {
		return nil, func() {}, fmt.Errorf("doh-enum: AWS credentials not available for gateway deployment: %w", err)
	}
	if creds.AccessKeyID == "" {
		return nil, func() {}, fmt.Errorf("doh-enum: AWS credentials not available for gateway deployment: no AWS credentials found")
	}

	var (
		mu        sync.Mutex
		created   []createdGateway
		endpoints []DoHEndpoint
	)

	var wg sync.WaitGroup
	sem := make(chan struct{}, 8) // limit concurrent deployments

	for _, server := range dohServers {
		for _, region := range defaultGatewayRegions {
			select {
			case <-ctx.Done():
				wg.Wait()
				return nil, func() {}, ctx.Err()
			default:
			}

			wg.Add(1)
			sem <- struct{}{}
			go func(server, region string) {
				defer wg.Done()

				var apiID, invokeURL string
				depErr := retryWithBackoff(ctx, gatewayAPIRetries, func() error {
					var err error
					apiID, invokeURL, err = deployGatewayInRegion(ctx, baseCfg, server, region)
					return err
				})

				<-sem // release semaphore before sleeping
				time.Sleep(500 * time.Millisecond)

				if depErr != nil {
					slog.Warn("doh-enum: failed to deploy gateway after retries", "server", server, "region", region, "error", depErr)
					return
				}

				slog.Info("doh-enum: deployed gateway", "api_id", apiID, "region", region, "invoke_url", invokeURL, "target", server)

				mu.Lock()
				created = append(created, createdGateway{apiID: apiID, region: region, invokeURL: invokeURL})
				endpoints = append(endpoints, DoHEndpoint{
					URL:  invokeURL,
					Name: fmt.Sprintf("gateway-%s-%s", region, apiID[:8]),
				})
				mu.Unlock()
			}(server, region)
		}
	}
	wg.Wait()

	if len(endpoints) == 0 {
		return nil, func() {}, fmt.Errorf("doh-enum: no gateways deployed successfully")
	}

	cleanup := func() {
		// Load a separate base config for cleanup since it uses context.Background().
		cleanupBaseCfg, cfgErr := config.LoadDefaultConfig(context.Background())
		if cfgErr != nil {
			slog.Warn("doh-enum: failed to load AWS config for cleanup", "error", cfgErr)
			return
		}

		// Group gateways by region so we can delete across regions concurrently
		// while spacing deletions within each region to respect per-region rate limits.
		byRegion := make(map[string][]createdGateway)
		for _, gw := range created {
			byRegion[gw.region] = append(byRegion[gw.region], gw)
		}

		var wg sync.WaitGroup
		for region, gws := range byRegion {
			wg.Add(1)
			go func(region string, gws []createdGateway) {
				defer wg.Done()
				for i, gw := range gws {
					if i > 0 {
						// 3s spacing between deletions in the same region.
						time.Sleep(3 * time.Second)
					}
					delErr := retryWithBackoff(context.Background(), gatewayAPIRetries, func() error {
						return deleteGatewayInRegion(context.Background(), cleanupBaseCfg, gw.apiID, gw.region)
					})
					if delErr != nil {
						slog.Warn("doh-enum: failed to delete gateway after all retries — manual deletion required",
							"api_id", gw.apiID, "region", gw.region, "error", delErr)
					} else {
						slog.Info("doh-enum: deleted gateway", "api_id", gw.apiID, "region", gw.region)
					}
				}
			}(region, gws)
		}
		wg.Wait()
	}

	return endpoints, cleanup, nil
}

// buildSwaggerBody creates the Swagger JSON body for a gateway targeting the given URL.
func buildSwaggerBody(targetURL string) ([]byte, error) {
	body := strings.ReplaceAll(swaggerTemplate, "{{url}}", targetURL)
	b := []byte(body)
	if !json.Valid(b) {
		return nil, fmt.Errorf("invalid swagger template")
	}
	return b, nil
}

// deployGatewayInRegion creates an API Gateway in the specified region using the
// Swagger import approach. Returns the apiID and invoke URL on success.
func deployGatewayInRegion(ctx context.Context, baseCfg aws.Config, targetURL, region string) (apiID, invokeURL string, err error) {
	cfg := baseCfg.Copy()
	cfg.Region = region

	svc := apigateway.NewFromConfig(cfg)

	swaggerBody, err := buildSwaggerBody(targetURL)
	if err != nil {
		return "", "", fmt.Errorf("build swagger body: %w", err)
	}

	importResult, err := svc.ImportRestApi(ctx, &apigateway.ImportRestApiInput{
		Body:           swaggerBody,
		FailOnWarnings: false,
		Parameters: map[string]string{
			"endpointConfigurationTypes": "REGIONAL",
		},
	})
	if err != nil {
		return "", "", fmt.Errorf("import REST API in %s: %w", region, err)
	}

	apiID = aws.ToString(importResult.Id)

	_, err = svc.CreateDeployment(ctx, &apigateway.CreateDeploymentInput{
		RestApiId: aws.String(apiID),
		StageName: aws.String("pius"),
	})
	if err != nil {
		// Clean up the API we just created. Retry the delete because we may
		// be rate-limited, and a silent failure here creates orphaned gateways.
		cleanupErr := retryWithBackoff(ctx, gatewayAPIRetries, func() error {
			_, delErr := svc.DeleteRestApi(ctx, &apigateway.DeleteRestApiInput{
				RestApiId: aws.String(apiID),
			})
			return delErr
		})
		if cleanupErr != nil {
			slog.Warn("doh-enum: failed to clean up API after deployment error — may be orphaned",
				"api_id", apiID, "region", region, "error", cleanupErr)
		}
		return "", "", fmt.Errorf("create deployment in %s: %w", region, err)
	}

	invokeURL = fmt.Sprintf("https://%s.execute-api.%s.amazonaws.com/pius", apiID, region)
	return apiID, invokeURL, nil
}

// deleteGatewayInRegion deletes an API Gateway REST API in the specified region.
func deleteGatewayInRegion(ctx context.Context, baseCfg aws.Config, apiID, region string) error {
	cfg := baseCfg.Copy()
	cfg.Region = region

	svc := apigateway.NewFromConfig(cfg)
	_, err := svc.DeleteRestApi(ctx, &apigateway.DeleteRestApiInput{
		RestApiId: aws.String(apiID),
	})
	if err != nil {
		return fmt.Errorf("delete REST API %s in %s: %w", apiID, region, err)
	}
	return nil
}

// retryWithBackoff retries op up to maxRetries times when a 429 TooManyRequests error is
// returned. The delay starts at 2 seconds and doubles on each attempt (2s, 4s, 8s, 16s, 32s).
// Context cancellation is respected between retries.
func retryWithBackoff(ctx context.Context, maxRetries int, op func() error) error {
	delay := 2 * time.Second
	var lastErr error
	for attempt := 0; attempt <= maxRetries; attempt++ {
		lastErr = op()
		if lastErr == nil {
			return nil
		}
		var apiErr smithy.APIError
		if !errors.As(lastErr, &apiErr) || apiErr.ErrorCode() != "TooManyRequestsException" {
			return lastErr
		}
		if attempt == maxRetries {
			break
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(delay):
		}
		delay *= 2
	}
	return lastErr
}
