package freeleh

import (
	"context"
	"errors"
	"regexp"

	"github.com/FreeLeh/GoFreeLeh/internal/google/sheets"
)

type KVMode int

type OrderBy string

const (
	KVModeDefault    KVMode = 0
	KVModeAppendOnly KVMode = 1

	OrderByAsc  OrderBy = "ASC"
	OrderByDesc OrderBy = "DESC"

	// Currently limited to 26.
	// Otherwise, the sheet creation must extend the column as well to make the rowGetIndicesQueryTemplate formula works.
	// TODO(edocsss): add an option to extend the number of columns.
	maxColumn = 26

	scratchpadBooked          = "BOOKED"
	scratchpadSheetNameSuffix = "_scratch"

	defaultKVTableRange    = "A1:C5000000"
	defaultKVKeyColRange   = "A1:A5000000"
	defaultKVFirstRowRange = "A1:C1"

	kvGetAppendQueryTemplate      = "=VLOOKUP(\"%s\", SORT(%s, 3, FALSE), 2, FALSE)"
	kvGetDefaultQueryTemplate     = "=VLOOKUP(\"%s\", %s, 2, FALSE)"
	kvFindKeyA1RangeQueryTemplate = "=MATCH(\"%s\", %s, 0)"

	rowGetIndicesQueryTemplate           = "=JOIN(\",\", ARRAYFORMULA(QUERY({%s, ROW(%s)}, \"%s\")))"
	rowUpdateModifyWhereNonEmptyTemplate = "%s IS NOT NULL AND %s"
	rowUpdateModifyWhereEmptyTemplate    = "%s IS NOT NULL"

	naValue    = "#N/A"
	errorValue = "#ERROR!"
	rowTsCol   = "_ts"
)

var (
	ErrKeyNotFound = errors.New("error key not found")

	defaultRowHeaderRange    = "A1:" + generateColumnName(maxColumn-1) + "1"
	defaultRowFullTableRange = "A2:" + generateColumnName(maxColumn-1)
	rowDeleteRangeTemplate   = "A%d:" + generateColumnName(maxColumn-1) + "%d"

	googleSheetSelectStmtStringKeyword = regexp.MustCompile("^(date|datetime|timeofday)")
)

type Codec interface {
	Encode(value []byte) (string, error)
	Decode(value string) ([]byte, error)
}

type sheetsWrapper interface {
	CreateSpreadsheet(ctx context.Context, title string) (string, error)
	GetSheetNameToID(ctx context.Context, spreadsheetID string) (map[string]int64, error)
	CreateSheet(ctx context.Context, spreadsheetID string, sheetName string) error
	DeleteSheets(ctx context.Context, spreadsheetID string, sheetIDs []int64) error
	InsertRows(ctx context.Context, spreadsheetID string, a1Range string, values [][]interface{}) (sheets.InsertRowsResult, error)
	OverwriteRows(ctx context.Context, spreadsheetID string, a1Range string, values [][]interface{}) (sheets.InsertRowsResult, error)
	UpdateRows(ctx context.Context, spreadsheetID string, a1Range string, values [][]interface{}) (sheets.UpdateRowsResult, error)
	BatchUpdateRows(ctx context.Context, spreadsheetID string, requests []sheets.BatchUpdateRowsRequest) (sheets.BatchUpdateRowsResult, error)
	QueryRows(ctx context.Context, spreadsheetID string, sheetName string, query string, skipHeader bool) (sheets.QueryRowsResult, error)
	Clear(ctx context.Context, spreadsheetID string, ranges []string) ([]string, error)
}

type colIdx struct {
	name string
	idx  int
}

type ColumnOrderBy struct {
	Column  string
	OrderBy OrderBy
}