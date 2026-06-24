/*
Copyright 2022 The Authors of https://github.com/CDK-TEAM/CDK .

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package exploit

import (
	// register all kinds of exploits
	_ "github.com/cdk-team/CDK/pkg/audit/credential_access"
	_ "github.com/cdk-team/CDK/pkg/audit/discovery"
	_ "github.com/cdk-team/CDK/pkg/audit/boundary"
	_ "github.com/cdk-team/CDK/pkg/audit/persistence"
	_ "github.com/cdk-team/CDK/pkg/audit/privilege_validation"
	_ "github.com/cdk-team/CDK/pkg/audit/remote_control"
)

func init() {
}
