/*
Copyright 2024 Codenotary Inc. All rights reserved.

SPDX-License-Identifier: BUSL-1.1
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    https://mariadb.com/bsl11/

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package bmessages

type Option func(s *errorResp)

// Severity the field contents are ERROR, FATAL, or PANIC (in an error message), or WARNING, NOTICE, DEBUG, INFO, or LOG (in a notice message), or a localized translation of one of these. Always present.
func Severity(value string) Option {
	return func(args *errorResp) {
		args.fields['S'] = value
	}
}

// Severity the field contents are ERROR, FATAL, or PANIC (in an error message), or WARNING, NOTICE, DEBUG, INFO, or LOG (in a notice message). This is identical to the S field except that the contents are never localized. This is present only in messages generated by PostgreSQL versions 9.6 and later.
func SeverityNotLoc(value string) Option {
	return func(args *errorResp) {
		args.fields['v'] = value
	}
}

// Code the SQLSTATE code for the error (see Appendix A). Not localizable. Always present.
func Code(value string) Option {
	return func(args *errorResp) {
		args.fields['C'] = value
	}
}

// Message the primary human-readable error message. This should be accurate but terse (typically one line). Always present.
func Message(value string) Option {
	return func(args *errorResp) {
		args.fields['M'] = value
	}
}

// Detail an optional secondary error message carrying more detail about the problem. Might run to multiple lines.
func Detail(value string) Option {
	return func(args *errorResp) {
		args.fields['D'] = value
	}
}

// Hint an optional suggestion what to do about the problem. This is intended to differ from Detail in that it offers advice (potentially inappropriate) rather than hard facts. Might run to multiple lines.
func Hint(value string) Option {
	return func(args *errorResp) {
		args.fields['H'] = value
	}
}

// Position the field value is a decimal ASCII integer, indicating an error cursor position as an index into the original query string. The first character has index 1, and positions are measured in characters not bytes.
func Position(value string) Option {
	return func(args *errorResp) {
		args.fields['P'] = value
	}
}

// InternalPosition this is defined the same as the P field, but it is used when the cursor position refers to an internally generated command rather than the one submitted by the client. The q field will always appear when this field appears.
func InternalPosition(value string) Option {
	return func(args *errorResp) {
		args.fields['p'] = value
	}
}

// InternalQuery the text of a failed internally-generated command. This could be, for example, a SQL query issued by a PL/pgSQL function.
func InternalQuery(value string) Option {
	return func(args *errorResp) {
		args.fields['q'] = value
	}
}

// Where an indication of the context in which the error occurred. Presently this includes a call stack traceback of active procedural language functions and internally-generated queries. The trace is one entry per line, most recent first.
func Where(value string) Option {
	return func(args *errorResp) {
		args.fields['W'] = value
	}
}

// SchemaName if the error was associated with a specific database object, the name of the schema containing that object, if any.
func SchemaName(value string) Option {
	return func(args *errorResp) {
		args.fields['s'] = value
	}
}

// TableName if the error was associated with a specific table, the name of the table. (Refer to the schema name field for the name of the table's schema.)
func TableName(value string) Option {
	return func(args *errorResp) {
		args.fields['t'] = value
	}
}

// ColumnName if the error was associated with a specific table column, the name of the column. (Refer to the schema and table name fields to identify the table.)
func ColumnName(value string) Option {
	return func(args *errorResp) {
		args.fields['c'] = value
	}
}

// DataTypeName if the error was associated with a specific data type, the name of the data type. (Refer to the schema name field for the name of the data type's schema.)
func DataTypeName(value string) Option {
	return func(args *errorResp) {
		args.fields['d'] = value
	}
}

// ConstraintName if the error was associated with a specific constraint, the name of the constraint. Refer to fields listed above for the associated table or domain. (For this purpose, indexes are treated as constraints, even if they weren't created with constraint syntax.)
func ConstraintName(value string) Option {
	return func(args *errorResp) {
		args.fields['n'] = value
	}
}

// File the file name of the source-code location where the error was reported.
func File(value string) Option {
	return func(args *errorResp) {
		args.fields['F'] = value
	}
}

// Line the line number of the source-code location where the error was reported.
func Line(value string) Option {
	return func(args *errorResp) {
		args.fields['L'] = value
	}
}

// Routine the name of the source-code routine reporting the error.
func Routine(value string) Option {
	return func(args *errorResp) {
		args.fields['R'] = value
	}
}
