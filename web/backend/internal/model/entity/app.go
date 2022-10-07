// =================================================================================
// Code generated by GoFrame CLI tool. DO NOT EDIT.
// =================================================================================

package entity

import (
	"github.com/gogf/gf/v2/os/gtime"
)

// App is the golang structure for table app.
type App struct {
	Id            int         `json:"id"            description:""`
	Domain        string      `json:"domain"        description:""`
	Appname       string      `json:"appname"       description:""`
	Appmaintainer string      `json:"appmaintainer" description:""`
	State         string      `json:"state"         description:""`
	Ratelimit     string      `json:"ratelimit"     description:""`
	Lmtime        string      `json:"lmtime"        description:""`
	Lmcount       string      `json:"lmcount"       description:""`
	Description   string      `json:"description"   description:""`
	Rule          string      `json:"rule"          description:""`
	CreateTime    *gtime.Time `json:"createTime"    description:""`
	UpdateTime    *gtime.Time `json:"updateTime"    description:""`
}
