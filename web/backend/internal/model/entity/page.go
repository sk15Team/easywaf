// =================================================================================
// Code generated by GoFrame CLI tool. DO NOT EDIT.
// =================================================================================

package entity

import (
	"github.com/gogf/gf/v2/os/gtime"
)

// Page is the golang structure for table page.
type Page struct {
	Id         int         `json:"id"         description:""`
	Domain     string      `json:"domain"     description:""`
	Action     string      `json:"action"     description:""`
	Uri        string      `json:"uri"        description:""`
	Method     string      `json:"method"     description:""`
	AddReason  string      `json:"addReason"  description:""`
	CreateTime *gtime.Time `json:"createTime" description:""`
	UpdateTime *gtime.Time `json:"updateTime" description:""`
}
