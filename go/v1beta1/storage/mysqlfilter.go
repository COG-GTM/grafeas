// Copyright 2019 The Grafeas Authors. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package storage

import (
	"fmt"
	"strings"

	"regexp"

	syntax "github.com/grafeas/grafeas/cel"
	"github.com/grafeas/grafeas/go/filtering/common"
	"github.com/grafeas/grafeas/go/filtering/operators"
	"github.com/grafeas/grafeas/go/filtering/parser"
)

//	var fs filterSql
//	sql, args, err := fs.ParseFilter(filter, "")

// identifierPattern matches the field and identifier names that are allowed to
// be interpolated into a JSON path. Anything else is rejected instead of being
// spliced into the query text.
var identifierPattern = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// indexPattern matches the rendering of an integer constant, the only thing
// allowed inside an index expression.
var indexPattern = regexp.MustCompile(`^\d+$`)

type MysqlFilterSql struct {
	selects     int
	data_prefix string
	// args holds the values bound to the placeholders emitted in the
	// generated SQL, in the order the placeholders appear.
	args []interface{}
}

func (fs *MysqlFilterSql) sqlFromCall(func_name string, args []*syntax.Expr) (string, error) {

	var sql_op string
	switch func_name {
	case operators.Equals:
		sql_op = "="
	case operators.Greater:
		sql_op = ">"
	case operators.GreaterEquals:
		sql_op = ">="
	case operators.Less:
		sql_op = "<"
	case operators.LessEquals:
		sql_op = "<="
	case operators.NotEquals:
		sql_op = "!="
	case operators.LogicalAnd:
		sql_op = "AND"
	case operators.LogicalOr:
		sql_op = "OR"
	case operators.Index:
		sql_op = "["
	case operators.LogicalNot:
		if len(args) != 1 {
			return "", fmt.Errorf("operator %q expects 1 argument, got %d", func_name, len(args))
		}
		arg, err := fs.makeSql(args[0])
		if err != nil {
			return "", err
		}
		return fmt.Sprintf("(NOT %s)", arg), nil
	default:
		// Anything that is not a known operator (arbitrary function calls,
		// unsupported CEL macros, ...) would end up as raw SQL text.
		return "", fmt.Errorf("unsupported operator or function %q in filter", func_name)
	}

	if len(args) != 2 {
		return "", fmt.Errorf("operator %q expects 2 arguments, got %d", func_name, len(args))
	}
	arg_names := make([]string, 0, len(args))
	for _, arg := range args {
		sql, err := fs.makeSql(arg)
		if err != nil {
			return "", err
		}
		arg_names = append(arg_names, sql)
	}
	if sql_op == "[" {
		// An index must be a literal position, never a bound value.
		if !indexPattern.MatchString(arg_names[1]) {
			return "", fmt.Errorf("index in filter must be an integer constant")
		}
		return fmt.Sprintf("%s[%s]", arg_names[0], arg_names[1]), nil
	}
	return fmt.Sprintf("(%s %s %s)", arg_names[0], sql_op, arg_names[1]), nil
}

func (fs *MysqlFilterSql) sqlFromSelect(select_node syntax.Expr_Select) (string, error) {
	operand, err := fs.makeSql(select_node.GetOperand())
	if err != nil {
		return "", err
	}
	field := select_node.GetField()
	if !identifierPattern.MatchString(field) {
		return "", fmt.Errorf("invalid field name %q in filter", field)
	}
	return fmt.Sprintf("%s.%s", operand, field), nil
}

// getConstantValue renders a constant. Numeric constants have no SQL syntax of
// their own so they are formatted inline; every other value is bound as a query
// parameter so that it can never alter the structure of the query.
func (fs *MysqlFilterSql) getConstantValue(const_expr syntax.Constant) (string, error) {

	switch const_expr.GetConstantKind().(type) {
	case *syntax.Constant_Int64Value:
		return fmt.Sprintf("%d", const_expr.GetInt64Value()), nil
	case *syntax.Constant_Uint64Value:
		return fmt.Sprintf("%d", const_expr.GetUint64Value()), nil
	case *syntax.Constant_DoubleValue:
		return fmt.Sprintf("%f", const_expr.GetDoubleValue()), nil
	case *syntax.Constant_StringValue:
		return fs.bind(const_expr.GetStringValue()), nil
	case *syntax.Constant_BoolValue:
		return fs.bind(const_expr.GetBoolValue()), nil
	}
	return "", fmt.Errorf("unsupported constant in filter")
}

// bind records value as a query parameter and returns its placeholder.
func (fs *MysqlFilterSql) bind(value interface{}) string {
	fs.args = append(fs.args, value)
	return "?"
}

func (fs *MysqlFilterSql) makeSql(node *syntax.Expr) (string, error) {
	switch node.GetExprKind().(type) {
	case *syntax.Expr_CallExpr:
		func_node := *node.GetCallExpr()
		return fs.sqlFromCall(func_node.Function, func_node.Args)
	case *syntax.Expr_SelectExpr:
		select_node := *node.GetSelectExpr()
		fs.selects++
		ret_str, err := fs.sqlFromSelect(select_node)
		fs.selects--
		if err != nil {
			return "", err
		}
		if fs.selects == 0 {
			return fs.data_prefix + "data->'$." + ret_str + "'", nil
		}
		return ret_str, nil
	case *syntax.Expr_IdentExpr:
		i_expr := *node.GetIdentExpr()
		if !identifierPattern.MatchString(i_expr.Name) {
			return "", fmt.Errorf("invalid identifier %q in filter", i_expr.Name)
		}
		// I'm not entirely sure this is the right thing here.
		// We'll see though.
		if fs.selects > 0 {
			return i_expr.Name, nil
		}
		return fs.data_prefix + "data->'$." + i_expr.Name + "'", nil
	case *syntax.Expr_ConstExpr:
		c_expr := *node.GetConstExpr()
		return fs.getConstantValue(c_expr)
	}

	return "", fmt.Errorf("unsupported expression in filter")
}

// ParseFilter translates a CEL filter expression into a SQL fragment and the
// values to bind to the placeholders it contains. The fragment never embeds
// caller supplied values, so it is safe to concatenate into a query template as
// long as the returned args are passed to the query in the same position.
func (fs *MysqlFilterSql) ParseFilter(filter string, data_prefix string) (string, []interface{}, error) {

	fs.data_prefix = data_prefix
	fs.args = nil
	fs.selects = 0

	if !isSafeDataPrefix(data_prefix) {
		return "", nil, fmt.Errorf("invalid data prefix %q", data_prefix)
	}

	// replace string value for kind with integer
	kindPattern := `kind=".*?"`
	re := regexp.MustCompile(kindPattern)
	indices := re.FindStringIndex(filter)
	if indices != nil {
		int_val := 0
		switch filter[indices[0]+6 : indices[1]-1] {
		case "VULNERABILITY":
			int_val = 1
		case "BUILD":
			int_val = 2
		case "IMAGE":
			int_val = 3
		case "PACKAGE":
			int_val = 4
		case "DEPLOYMENT":
			int_val = 5
		case "DISCOVERY":
			int_val = 6
		case "ATTESTATION":
			int_val = 7
		case "INTOTO":
			int_val = 8
		}
		filter = filter[:indices[0]+5] + fmt.Sprintf("%d", int_val) + filter[indices[1]:]
	}
	s := common.NewStringSource(filter, "urlParam") // function
	result, parseErrs := parser.Parse(s)
	if parseErrs != nil {
		return "", nil, fmt.Errorf("failed to parse filter: %s", parseErrs.String())
	}
	sql, err := fs.makeSql(result.Expr)
	if err != nil {
		return "", nil, err
	}
	return sql, fs.args, nil
}

// isSafeDataPrefix guards the table alias prefix used in the generated JSON
// paths. It is set by the storage layer, never by a caller of the API, but it
// is validated to keep the SQL construction free of unchecked interpolation.
func isSafeDataPrefix(prefix string) bool {
	if prefix == "" {
		return true
	}
	return identifierPattern.MatchString(strings.TrimSuffix(prefix, "."))
}
