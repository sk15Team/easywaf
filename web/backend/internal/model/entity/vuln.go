// =================================================================================
// Code generated by GoFrame CLI tool. DO NOT EDIT.
// =================================================================================

package entity

import (
	"github.com/gogf/gf/v2/os/gtime"
)

// Vuln is the golang structure for table vuln.
type Vuln struct {
	Id         int         `json:"id"         description:""`
	Name       string      `json:"name"       description:""`
	Key        string      `json:"key"        description:""`
	CreateTime *gtime.Time `json:"createTime" description:""`
	UpdateTime *gtime.Time `json:"updateTime" description:""`
}
