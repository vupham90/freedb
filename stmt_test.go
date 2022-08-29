package freedb

import (
	"context"
	"errors"
	"testing"

	"github.com/FreeLeh/GoFreeDB/internal/google/sheets"
	"github.com/stretchr/testify/assert"
)

type person struct {
	Name string `db:"name,omitempty"`
	Age  int    `db:"age,omitempty"`
	DOB  string `db:"dob,omitempty"`
}

func TestGenerateQuery(t *testing.T) {
	colsMapping := colsMapping{rowIdxCol: {"A", 0}, "col1": {"B", 1}, "col2": {"C", 2}}

	t.Run("successful_basic", func(t *testing.T) {
		builder := newQueryBuilder(colsMapping.NameMap(), ridWhereClauseInterceptor, []string{"col1", "col2"})
		result, err := builder.Generate()
		assert.Nil(t, err)
		assert.Equal(t, "select B, C where A is not null", result)
	})

	t.Run("unsuccessful_basic_wrong_column", func(t *testing.T) {
		builder := newQueryBuilder(colsMapping.NameMap(), ridWhereClauseInterceptor, []string{"col1", "col2", "col3"})
		result, err := builder.Generate()
		assert.Nil(t, err)
		assert.Equal(t, "select B, C, col3 where A is not null", result)
	})

	t.Run("successful_with_where", func(t *testing.T) {
		builder := newQueryBuilder(colsMapping.NameMap(), ridWhereClauseInterceptor, []string{"col1", "col2"})
		builder.Where("(col1 > ? AND col2 <= ?) OR (col1 != ? AND col2 == ?)", 100, true, "value", 3.14)

		result, err := builder.Generate()
		assert.Nil(t, err)
		assert.Equal(t, "select B, C where A is not null AND (B > 100 AND C <= true ) OR (B != 'value' AND C == 3.14 )", result)
	})

	t.Run("unsuccessful_with_where_wrong_arg_count", func(t *testing.T) {
		builder := newQueryBuilder(colsMapping.NameMap(), ridWhereClauseInterceptor, []string{"col1", "col2"})
		builder.Where("(col1 > ? AND col2 <= ?) OR (col1 != ? AND col2 == ?)", 100, true)

		result, err := builder.Generate()
		assert.NotNil(t, err)
		assert.Equal(t, "", result)
	})

	t.Run("unsuccessful_with_where_unsupported_arg_type", func(t *testing.T) {
		builder := newQueryBuilder(colsMapping.NameMap(), ridWhereClauseInterceptor, []string{"col1", "col2"})
		builder.Where("(col1 > ? AND col2 <= ?) OR (col1 != ? AND col2 == ?)", 100, true, nil, []string{})

		result, err := builder.Generate()
		assert.NotNil(t, err)
		assert.Equal(t, "", result)
	})

	t.Run("successful_with_limit_offset", func(t *testing.T) {
		builder := newQueryBuilder(colsMapping.NameMap(), ridWhereClauseInterceptor, []string{"col1", "col2"})
		builder.Limit(10).Offset(100)

		result, err := builder.Generate()
		assert.Nil(t, err)
		assert.Equal(t, "select B, C where A is not null offset 100 limit 10", result)
	})

	t.Run("successful_with_order_by", func(t *testing.T) {
		builder := newQueryBuilder(colsMapping.NameMap(), ridWhereClauseInterceptor, []string{"col1", "col2"})
		builder.OrderBy([]ColumnOrderBy{{Column: "col2", OrderBy: OrderByDesc}, {Column: "col1", OrderBy: OrderByAsc}})

		result, err := builder.Generate()
		assert.Nil(t, err)
		assert.Equal(t, "select B, C where A is not null order by C DESC, B ASC", result)
	})
}

func TestSelectStmt_AllColumns(t *testing.T) {
	store := &GoogleSheetRowStore{
		colsMapping: colsMapping{rowIdxCol: {"A", 0}, "col1": {"B", 1}, "col2": {"C", 2}},
		config:      GoogleSheetRowStoreConfig{Columns: []string{"col1", "col2"}},
	}
	stmt := newGoogleSheetSelectStmt(store, nil, []string{})

	result, err := stmt.queryBuilder.Generate()
	assert.Nil(t, err)
	assert.Equal(t, "select B, C where A is not null", result)
}

func TestSelectStmt_Exec(t *testing.T) {
	t.Run("non_slice_output", func(t *testing.T) {
		wrapper := &sheets.MockWrapper{}
		store := &GoogleSheetRowStore{
			wrapper:     wrapper,
			colsMapping: map[string]colIdx{rowIdxCol: {"A", 0}, "col1": {"B", 1}, "col2": {"C", 2}},
		}
		o := 0
		stmt := newGoogleSheetSelectStmt(store, &o, []string{"col1", "col2"})

		assert.NotNil(t, stmt.Exec(context.Background()))
	})

	t.Run("non_pointer_to_slice_output", func(t *testing.T) {
		wrapper := &sheets.MockWrapper{}
		store := &GoogleSheetRowStore{
			wrapper:     wrapper,
			colsMapping: map[string]colIdx{rowIdxCol: {"A", 0}, "col1": {"B", 1}, "col2": {"C", 2}},
		}
		var o []int
		stmt := newGoogleSheetSelectStmt(store, o, []string{"col1", "col2"})

		assert.NotNil(t, stmt.Exec(context.Background()))
	})

	t.Run("nil_output", func(t *testing.T) {
		wrapper := &sheets.MockWrapper{}
		store := &GoogleSheetRowStore{
			wrapper:     wrapper,
			colsMapping: map[string]colIdx{rowIdxCol: {"A", 0}, "col1": {"B", 1}, "col2": {"C", 2}},
		}
		stmt := newGoogleSheetSelectStmt(store, nil, []string{"col1", "col2"})

		assert.NotNil(t, stmt.Exec(context.Background()))
	})

	t.Run("has_query_error", func(t *testing.T) {
		wrapper := &sheets.MockWrapper{QueryRowsError: errors.New("some error")}
		store := &GoogleSheetRowStore{
			wrapper:     wrapper,
			colsMapping: map[string]colIdx{rowIdxCol: {"A", 0}, "col1": {"B", 1}, "col2": {"C", 2}},
		}
		var out []int
		stmt := newGoogleSheetSelectStmt(store, &out, []string{"col1", "col2"})

		err := stmt.Exec(context.Background())
		assert.NotNil(t, err)
	})

	t.Run("successful", func(t *testing.T) {
		wrapper := &sheets.MockWrapper{QueryRowsResult: sheets.QueryRowsResult{Rows: [][]interface{}{
			{10, "17-01-2001"},
			{11, "18-01-2000"},
		}}}
		store := &GoogleSheetRowStore{
			wrapper:     wrapper,
			colsMapping: map[string]colIdx{rowIdxCol: {"A", 0}, "name": {"B", 1}, "age": {"C", 2}, "dob": {"D", 3}},
			config: GoogleSheetRowStoreConfig{
				Columns: []string{"name", "age", "dob"},
			},
		}
		var out []person
		stmt := newGoogleSheetSelectStmt(store, &out, []string{"age", "dob"})

		expected := []person{
			{Age: 10, DOB: "17-01-2001"},
			{Age: 11, DOB: "18-01-2000"},
		}
		err := stmt.Exec(context.Background())

		assert.Nil(t, err)
		assert.Equal(t, expected, out)
	})

	t.Run("successful_select_all", func(t *testing.T) {
		wrapper := &sheets.MockWrapper{QueryRowsResult: sheets.QueryRowsResult{Rows: [][]interface{}{
			{"name1", 10, "17-01-2001"},
			{"name2", 11, "18-01-2000"},
		}}}
		store := &GoogleSheetRowStore{
			wrapper:     wrapper,
			colsMapping: map[string]colIdx{rowIdxCol: {"A", 0}, "name": {"B", 1}, "age": {"C", 2}, "dob": {"D", 3}},
			config: GoogleSheetRowStoreConfig{
				Columns: []string{"name", "age", "dob"},
			},
		}
		var out []person
		stmt := newGoogleSheetSelectStmt(store, &out, []string{})

		expected := []person{
			{Name: "name1", Age: 10, DOB: "17-01-2001"},
			{Name: "name2", Age: 11, DOB: "18-01-2000"},
		}
		err := stmt.Exec(context.Background())

		assert.Nil(t, err)
		assert.Equal(t, expected, out)
	})
}

func TestGoogleSheetInsertStmt_convertRowToSlice(t *testing.T) {
	wrapper := &sheets.MockWrapper{}
	store := &GoogleSheetRowStore{
		wrapper:     wrapper,
		colsMapping: map[string]colIdx{rowIdxCol: {"A", 0}, "name": {"B", 1}, "age": {"C", 2}, "dob": {"D", 3}},
		config: GoogleSheetRowStoreConfig{
			Columns: []string{"name", "age", "dob"},
		},
	}

	t.Run("non_struct", func(t *testing.T) {
		stmt := newGoogleSheetInsertStmt(store, nil)

		result, err := stmt.convertRowToSlice(nil)
		assert.Nil(t, result)
		assert.NotNil(t, err)

		result, err = stmt.convertRowToSlice(1)
		assert.Nil(t, result)
		assert.NotNil(t, err)

		result, err = stmt.convertRowToSlice("1")
		assert.Nil(t, result)
		assert.NotNil(t, err)

		result, err = stmt.convertRowToSlice([]int{1, 2, 3})
		assert.Nil(t, result)
		assert.NotNil(t, err)
	})

	t.Run("struct", func(t *testing.T) {
		stmt := newGoogleSheetInsertStmt(store, nil)

		result, err := stmt.convertRowToSlice(person{Name: "blah", Age: 10, DOB: "2021"})
		assert.Equal(t, []interface{}{rowIdxFormula, "blah", 10, "2021"}, result)
		assert.Nil(t, err)

		result, err = stmt.convertRowToSlice(&person{Name: "blah", Age: 10, DOB: "2021"})
		assert.Equal(t, []interface{}{rowIdxFormula, "blah", 10, "2021"}, result)
		assert.Nil(t, err)

		result, err = stmt.convertRowToSlice(person{Name: "blah", DOB: "2021"})
		assert.Equal(t, []interface{}{rowIdxFormula, "blah", nil, "2021"}, result)
		assert.Nil(t, err)

		type dummy struct {
			Name string `db:"name"`
		}

		result, err = stmt.convertRowToSlice(dummy{Name: "blah"})
		assert.Equal(t, []interface{}{rowIdxFormula, "blah", nil, nil}, result)
		assert.Nil(t, err)
	})
}
