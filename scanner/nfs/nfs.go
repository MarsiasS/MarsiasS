package nfs

import "time"

type Export struct {
	Path   string
	Groups []string
}

type NFSResult struct {
	ErrorMessage   string
	VersionSummary string
	PortmapperAlive bool
	MountdPort     int
	Exports        []Export
	Anonymous      bool
}

func ScanNFS(target string, timeout time.Duration) NFSResult {
	return NFSResult{
		VersionSummary: "",
		PortmapperAlive: false,
		MountdPort: 0,
		Exports: []Export{},
		Anonymous: false,
	}
}