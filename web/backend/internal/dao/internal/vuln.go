// ==========================================================================
// Code generated by GoFrame CLI tool. DO NOT EDIT.
// ==========================================================================

package internal

import (
	"context"

	"github.com/gogf/gf/v2/database/gdb"
	"github.com/gogf/gf/v2/frame/g"
)

// VulnDao is the data access object for table vuln.
type VulnDao struct {
	table   string      // table is the underlying table name of the DAO.
	group   string      // group is the database configuration group name of current DAO.
	columns VulnColumns // columns contains all the column names of Table for convenient usage.
}

// VulnColumns defines and stores column names for table vuln.
type VulnColumns struct {
	Id         string //
	Name       string //
	Key        string //
	CreateTime string //
	UpdateTime string //
}

//  vulnColumns holds the columns for table vuln.
var vulnColumns = VulnColumns{
	Id:         "id",
	Name:       "name",
	Key:        "key",
	CreateTime: "create_time",
	UpdateTime: "update_time",
}

// NewVulnDao creates and returns a new DAO object for table data access.
func NewVulnDao() *VulnDao {
	return &VulnDao{
		group:   "default",
		table:   "vuln",
		columns: vulnColumns,
	}
}

// DB retrieves and returns the underlying raw database management object of current DAO.
func (dao *VulnDao) DB() gdb.DB {
	return g.DB(dao.group)
}

// Table returns the table name of current dao.
func (dao *VulnDao) Table() string {
	return dao.table
}

// Columns returns all column names of current dao.
func (dao *VulnDao) Columns() VulnColumns {
	return dao.columns
}

// Group returns the configuration group name of database of current dao.
func (dao *VulnDao) Group() string {
	return dao.group
}

// Ctx creates and returns the Model for current DAO, It automatically sets the context for current operation.
func (dao *VulnDao) Ctx(ctx context.Context) *gdb.Model {
	return dao.DB().Model(dao.table).Safe().Ctx(ctx)
}

// Transaction wraps the transaction logic using function f.
// It rollbacks the transaction and returns the error from function f if it returns non-nil error.
// It commits the transaction and returns nil if function f returns nil.
//
// Note that, you should not Commit or Rollback the transaction in function f
// as it is automatically handled by this function.
func (dao *VulnDao) Transaction(ctx context.Context, f func(ctx context.Context, tx *gdb.TX) error) (err error) {
	return dao.Ctx(ctx).Transaction(ctx, f)
}