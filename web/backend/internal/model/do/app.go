// =================================================================================
// Code generated by GoFrame CLI tool. DO NOT EDIT.
// =================================================================================

package do

import (
	"github.com/gogf/gf/v2/frame/g"
	"github.com/gogf/gf/v2/os/gtime"
)

// App is the golang structure of table app for DAO operations like Where/Data.
type App struct {
	g.Meta        `orm:"table:app, do:true"`
	Id            interface{} //
	Domain        interface{} //
	Appname       interface{} //
	Appmaintainer interface{} //
	State         interface{} //
	Ratelimit     interface{} //
	Lmtime        interface{} //
	Lmcount       interface{} //
	Description   interface{} //
	Rule          interface{} //
	CreateTime    *gtime.Time //
	UpdateTime    *gtime.Time //
}
