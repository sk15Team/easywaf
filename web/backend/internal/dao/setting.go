// =================================================================================
// This is auto-generated by GoFrame CLI tool only once. Fill this file as you wish.
// =================================================================================

package dao

import (
	"waf/internal/dao/internal"
)

// internalSettingDao is internal type for wrapping internal DAO implements.
type internalSettingDao = *internal.SettingDao

// settingDao is the data access object for table setting.
// You can define custom methods on it to extend its functionality as you wish.
type settingDao struct {
	internalSettingDao
}

var (
	// Setting is globally public accessible object for table setting operations.
	Setting = settingDao{
		internal.NewSettingDao(),
	}
)

// Fill with you ideas below.
