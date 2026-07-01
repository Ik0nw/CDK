package persistence

import "github.com/cdk-team/CDK/pkg/util"

func writeAuditManifest(kind, name, content string) string {
	return util.WriteAuditManifest(kind, name, content)
}
