// =================================================================================
// This is auto-generated by GoFrame CLI tool only once. Fill this file as you wish.
// =================================================================================

package dao

import (
	"waf/internal/dao/internal"
)

// internalVulnDao is internal type for wrapping internal DAO implements.
type internalVulnDao = *internal.VulnDao

// vulnDao is the data access object for table vuln.
// You can define custom methods on it to extend its functionality as you wish.
type vulnDao struct {
	internalVulnDao
}

var (
	// Vuln is globally public accessible object for table vuln operations.
	Vuln = vulnDao{
		internal.NewVulnDao(),
	}
)

// Fill with you ideas below.
