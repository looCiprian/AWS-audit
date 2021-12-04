package vuln

func (severity VulnerabilitySeverityValue) getSeverityString() string {
	switch severity {
	case SeverityInfo:
		return "Info"
	case SeverityLow:
		return "Low"
	case SeverityMedium:
		return "Medium"
	case SeverityHigh:
		return "High"
	default:
		return "Unknown"
	}
}
