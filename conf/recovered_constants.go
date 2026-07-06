package conf

const K8sSATokenDefaultPath = "/var/run/secrets/kubernetes.io/serviceaccount/token"

type scanFileTextConf struct { MaxFileByte int64; SkipExecutableFile bool; RegexList map[string]string }
var ScanFileTextConf = scanFileTextConf{ MaxFileByte: 1024*1024, SkipExecutableFile: true, RegexList: map[string]string{ "jwt": "eyJ" } }
// File upload handler templates for web application security testing.
// Used by the "deploy-debug-shell" audit module to validate that
// web application file upload endpoints are properly restricted.
const FileUploadTemplatePHP = "php-upload-validator"
const FileUploadTemplateJSP = "jsp-upload-validator"

