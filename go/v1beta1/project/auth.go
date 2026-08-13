// Copyright 2019 The Grafeas Authors. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package project

import (
	"github.com/grafeas/grafeas/go/iam"
	"golang.org/x/net/context"
)

const (
	// ProjectsGet is the permission to get a project.
	ProjectsGet = iam.Permission("projects.get")
	// ProjectsList is the permission to list projects.
	ProjectsList = iam.Permission("projects.list")
	// ProjectsCreate is the permission to create a project.
	ProjectsCreate = iam.Permission("projects.create")
	// ProjectsDelete is the permission to delete a project.
	ProjectsDelete = iam.Permission("projects.delete")

	// Projects is the resource type for projects.
	Projects = iam.Resource("projects")
)

// Auth provides authorization functions for this API. It is a subset of the auth interface used by
// the Grafeas notes and occurrences API, so the same implementation can be shared by both.
type Auth interface {
	// CheckAccessAndProject checks to see whether an API call is allowed. This method should
	// generally be the first thing an API method calls before taking any action. To prevent leaking
	// information, the only kind of error this should return is a permission denied error. Calls
	// that are not scoped to a single project, such as listing projects, pass an empty project ID.
	CheckAccessAndProject(ctx context.Context, projectID string, entityID string, p iam.Permission) error
	// PurgePolicy purges any auth policies that may have been set on the specified entity if using
	// an IAM service.
	PurgePolicy(ctx context.Context, projectID string, entityID string, r iam.Resource) error
}

// NoOpAuth does nothing.
type NoOpAuth struct{}

func (a *NoOpAuth) CheckAccessAndProject(ctx context.Context, projectID string, entityID string, p iam.Permission) error {
	return nil
}

func (a *NoOpAuth) PurgePolicy(ctx context.Context, projectID string, entityID string, r iam.Resource) error {
	return nil
}
