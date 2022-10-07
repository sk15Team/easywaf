// =================================================================================
// This is auto-generated by GoFrame CLI tool only once. Fill this file as you wish.
// =================================================================================

package dao

import (
	"waf/internal/dao/internal"
)

// internalPageDao is internal type for wrapping internal DAO implements.
type internalPageDao = *internal.PageDao

// pageDao is the data access object for table page.
// You can define custom methods on it to extend its functionality as you wish.
type pageDao struct {
	internalPageDao
}

var (
	// Page is globally public accessible object for table page operations.
	Page = pageDao{
		internal.NewPageDao(),
	}
)

// Fill with you ideas below.
