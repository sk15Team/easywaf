// =================================================================================
// Code generated by GoFrame CLI tool. DO NOT EDIT.
// =================================================================================

package do

import (
	"github.com/gogf/gf/v2/frame/g"
)

// Setting is the golang structure of table setting for DAO operations like Where/Data.
type Setting struct {
	g.Meta `orm:"table:setting, do:true"`
	Id     interface{} //
	Group  interface{} //
	Key    interface{} //
	Value  interface{} //
}