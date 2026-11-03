package validator

import (
	"testing"

	"github.com/compliancetf/ctfkit/internal/config"
	"github.com/compliancetf/ctfkit/internal/parser"
)

func TestEndpointValidator(t *testing.T) {
	tests := []struct {
		name          string
		module        parser.Module
		config        *config.Config
		wantViolation bool
	}{
		{
			name: "allowed CTF module",
			module: parser.Module{
				Name:   "s3",
				Source: "soc2.compliance.tf/terraform-aws-modules/s3-bucket/aws",
			},
			config: &config.Config{
				AllowedEndpoints: []string{"soc2.compliance.tf"},
			},
			wantViolation: false,
		},
		{
			name: "non-CTF module",
			module: parser.Module{
				Name:   "s3",
				Source: "terraform-aws-modules/s3/aws",
			},
			config: &config.Config{
				AllowedEndpoints: []string{"soc2.compliance.tf"},
			},
			wantViolation: true,
		},
		{
			name: "local module allowed",
			module: parser.Module{
				Name:   "local",
				Source: "./modules/vpc",
			},
			config: &config.Config{
				AllowedEndpoints: []string{"soc2.compliance.tf"},
			},
			wantViolation: false,
		},
		{
			name: "git source with CTF endpoint",
			module: parser.Module{
				Name:   "vpc",
				Source: "git::https://github.com/soc2.compliance.tf/modules.git",
			},
			config: &config.Config{
				AllowedEndpoints: []string{"soc2.compliance.tf"},
			},
			wantViolation: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := NewEndpointValidator(tt.config)
			violations := v.Validate(ValidationInput{
				Modules: []parser.Module{tt.module},
				Config:  tt.config,
			})

			if tt.wantViolation && len(violations) == 0 {
				t.Error("expected violation but got none")
			}
			if !tt.wantViolation && len(violations) > 0 {
				t.Errorf("unexpected violation: %v", violations[0])
			}
		})
	}
}

func TestControlDisableDetector(t *testing.T) {
	tests := []struct {
		name          string
		module        parser.Module
		config        *config.Config
		wantViolation bool
	}{
		{
			name: "module with disable parameter",
			module: parser.Module{
				Name:   "vpc",
				Source: "soc2.compliance.tf/modules/vpc/aws?disable_compliance=true",
			},
			config: &config.Config{
				DisablePatterns:      []string{"disable_", "skip_"},
				FailOnControlDisable: true,
			},
			wantViolation: true,
		},
		{
			name: "module with skip variable",
			module: parser.Module{
				Name:   "vpc",
				Source: "soc2.compliance.tf/modules/vpc/aws",
				Variables: map[string]interface{}{
					"skip_validation": true,
				},
			},
			config: &config.Config{
				DisablePatterns:      []string{"disable_", "skip_"},
				FailOnControlDisable: true,
			},
			wantViolation: true,
		},
		{
			name: "clean module",
			module: parser.Module{
				Name:   "vpc",
				Source: "soc2.compliance.tf/modules/vpc/aws",
				Variables: map[string]interface{}{
					"cidr": "10.0.0.0/16",
				},
			},
			config: &config.Config{
				DisablePatterns:      []string{"disable_", "skip_"},
				FailOnControlDisable: true,
			},
			wantViolation: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := NewControlDisableDetector(tt.config)
			violations := v.Validate(ValidationInput{
				Modules: []parser.Module{tt.module},
				Config:  tt.config,
			})

			if tt.wantViolation && len(violations) == 0 {
				t.Error("expected violation but got none")
			}
			if !tt.wantViolation && len(violations) > 0 {
				t.Errorf("unexpected violation: %v", violations[0])
			}
		})
	}
}

func TestResourceTypeValidator(t *testing.T) {
	tests := []struct {
		name          string
		resource      parser.Resource
		config        *config.Config
		wantViolation bool
	}{
		{
			name: "allowed resource type",
			resource: parser.Resource{
				Type: "aws_s3_bucket",
				Name: "example",
			},
			config: &config.Config{
				AllowedResources: []string{"aws_s3_bucket", "aws_ec2_instance"},
			},
			wantViolation: false,
		},
		{
			name: "disallowed resource type",
			resource: parser.Resource{
				Type: "aws_iam_role",
				Name: "admin",
			},
			config: &config.Config{
				AllowedResources: []string{"aws_s3_bucket", "aws_ec2_instance"},
			},
			wantViolation: true,
		},
		{
			name: "no restrictions",
			resource: parser.Resource{
				Type: "aws_iam_role",
				Name: "admin",
			},
			config: &config.Config{
				AllowedResources: []string{},
			},
			wantViolation: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := NewResourceTypeValidator(tt.config)
			violations := v.Validate(ValidationInput{
				Resources: []parser.Resource{tt.resource},
				Config:    tt.config,
			})

			if tt.wantViolation && len(violations) == 0 {
				t.Error("expected violation but got none")
			}
			if !tt.wantViolation && len(violations) > 0 {
				t.Errorf("unexpected violation: %v", violations[0])
			}
		})
	}
}
