// Code generated by goyacc -l -o sql_parser.go sql_grammar.y. DO NOT EDIT.
package sql

import __yyfmt__ "fmt"

func setResult(l yyLexer, stmts []SQLStmt) {
	l.(*lexer).result = stmts
}

type yySymType struct {
	yys      int
	stmts    []SQLStmt
	stmt     SQLStmt
	colsSpec []*ColSpec
	colSpec  *ColSpec
	cols     []*ColSelector
	rows     []*RowSpec
	row      *RowSpec
	values   []Value
	value    Value
	id       string
	number   uint64
	str      string
	boolean  bool
	blob     []byte
	sqlType  SQLValueType
	aggFn    AggregateFn
	ids      []string
	col      *ColSelector
	sel      Selector
	sels     []Selector
	distinct bool
	ds       DataSource
	tableRef *TableRef
	joins    []*JoinSpec
	join     *JoinSpec
	joinType JoinType
	boolExp  BoolExp
	err      error
	ordcols  []*OrdCol
	opt_ord  Comparison
	logicOp  LogicOperator
	cmpOp    CmpOperator
}

const CREATE = 57346
const USE = 57347
const DATABASE = 57348
const SNAPSHOT = 57349
const SINCE = 57350
const UP = 57351
const TO = 57352
const TABLE = 57353
const INDEX = 57354
const ON = 57355
const ALTER = 57356
const ADD = 57357
const COLUMN = 57358
const PRIMARY = 57359
const KEY = 57360
const BEGIN = 57361
const TRANSACTION = 57362
const COMMIT = 57363
const UPSERT = 57364
const INTO = 57365
const VALUES = 57366
const SELECT = 57367
const DISTINCT = 57368
const FROM = 57369
const JOIN = 57370
const HAVING = 57371
const WHERE = 57372
const GROUP = 57373
const BY = 57374
const LIMIT = 57375
const ORDER = 57376
const ASC = 57377
const DESC = 57378
const AS = 57379
const NOT = 57380
const LIKE = 57381
const EXISTS = 57382
const JOINTYPE = 57383
const LOP = 57384
const CMPOP = 57385
const IDENTIFIER = 57386
const TYPE = 57387
const NUMBER = 57388
const STRING = 57389
const BOOLEAN = 57390
const BLOB = 57391
const AGGREGATE_FUNC = 57392
const ERROR = 57393
const STMT_SEPARATOR = 57394

var yyToknames = [...]string{
	"$end",
	"error",
	"$unk",
	"CREATE",
	"USE",
	"DATABASE",
	"SNAPSHOT",
	"SINCE",
	"UP",
	"TO",
	"TABLE",
	"INDEX",
	"ON",
	"ALTER",
	"ADD",
	"COLUMN",
	"PRIMARY",
	"KEY",
	"BEGIN",
	"TRANSACTION",
	"COMMIT",
	"UPSERT",
	"INTO",
	"VALUES",
	"SELECT",
	"DISTINCT",
	"FROM",
	"JOIN",
	"HAVING",
	"WHERE",
	"GROUP",
	"BY",
	"LIMIT",
	"ORDER",
	"ASC",
	"DESC",
	"AS",
	"NOT",
	"LIKE",
	"EXISTS",
	"JOINTYPE",
	"LOP",
	"CMPOP",
	"IDENTIFIER",
	"TYPE",
	"NUMBER",
	"STRING",
	"BOOLEAN",
	"BLOB",
	"AGGREGATE_FUNC",
	"ERROR",
	"','",
	"'.'",
	"STMT_SEPARATOR",
	"'('",
	"')'",
	"'@'",
	"'*'",
}
var yyStatenames = [...]string{}

const yyEofCode = 1
const yyErrCode = 2
const yyInitialStackSize = 16

var yyExca = [...]int{
	-1, 1,
	1, -1,
	-2, 0,
}

const yyPrivate = 57344

const yyLast = 212

var yyAct = [...]int{

	118, 180, 51, 133, 117, 119, 6, 65, 74, 85,
	66, 7, 47, 36, 167, 120, 99, 122, 166, 172,
	98, 123, 34, 124, 125, 126, 127, 70, 138, 139,
	164, 162, 121, 151, 128, 124, 125, 126, 127, 130,
	44, 111, 160, 48, 45, 144, 128, 12, 13, 105,
	54, 34, 144, 134, 71, 67, 143, 14, 91, 90,
	76, 60, 55, 53, 64, 15, 3, 18, 92, 61,
	54, 179, 171, 148, 89, 93, 48, 83, 88, 16,
	2, 49, 33, 36, 159, 17, 19, 112, 97, 35,
	170, 104, 78, 106, 107, 57, 102, 3, 30, 9,
	31, 94, 110, 109, 36, 147, 50, 138, 139, 103,
	145, 129, 114, 108, 75, 95, 82, 81, 45, 72,
	69, 56, 45, 43, 40, 141, 142, 38, 63, 37,
	75, 139, 87, 68, 140, 181, 182, 169, 156, 52,
	150, 154, 153, 157, 158, 175, 137, 116, 4, 101,
	161, 163, 165, 136, 22, 9, 12, 13, 113, 29,
	12, 13, 62, 20, 131, 79, 14, 146, 59, 28,
	14, 174, 176, 173, 15, 8, 178, 23, 15, 46,
	183, 9, 24, 25, 96, 184, 39, 58, 41, 42,
	77, 26, 27, 168, 177, 152, 115, 135, 100, 86,
	84, 21, 32, 149, 132, 155, 80, 73, 11, 10,
	5, 1,
}
var yyPact = [...]int{

	12, -1000, 156, 12, -1000, 13, 12, -1000, 143, 128,
	-1000, -1000, 171, 185, 158, 136, -1000, -1000, 12, -1000,
	12, 39, -1000, 85, 83, 173, 80, 180, 79, 78,
	156, 152, 54, -1000, 102, 8, 17, -1000, 7, 77,
	-1000, 48, 177, 153, 6, 16, -1000, 141, 10, 0,
	39, -1000, 76, -31, 75, 70, 5, 181, 45, 149,
	73, 72, -1000, -1000, 43, 91, -1000, 74, -1000, -1000,
	3, 2, 15, 23, -1000, 56, 71, 174, -1000, 70,
	-36, -1000, -1000, -1000, 119, -1000, 91, 81, 102, -7,
	102, 102, 69, 86, -1000, -15, 40, -1000, 134, 68,
	116, -23, -1000, 0, -17, -1000, -1000, -1000, -1000, 146,
	-1000, -1000, -1000, -2, -1000, 124, 114, 65, 95, -1000,
	-23, -23, 1, -3, -1000, -1000, -1000, -1000, 66, 154,
	-1000, 61, 21, -1000, -11, 109, -23, 60, -23, -23,
	37, 88, -14, 130, -25, -1000, -23, -26, -2, -38,
	-1000, -10, 103, 44, 65, 20, -1000, 88, -1000, -1000,
	-1000, -37, -1000, 65, -1000, -1000, -1000, -11, 102, 113,
	-1000, 60, -1000, -1000, -1000, 60, -1000, 19, 100, 60,
	-1000, -1000, -1000, 100, -1000,
}
var yyPgo = [...]int{

	0, 211, 148, 12, 210, 11, 209, 208, 6, 207,
	8, 206, 205, 204, 3, 203, 5, 82, 202, 0,
	201, 7, 10, 200, 9, 199, 4, 198, 197, 196,
	195, 2, 194, 193, 1, 79,
}
var yyR1 = [...]int{

	0, 1, 2, 2, 2, 35, 35, 4, 4, 5,
	5, 3, 3, 6, 6, 6, 6, 6, 6, 6,
	6, 7, 13, 13, 14, 11, 11, 12, 12, 15,
	15, 16, 16, 16, 16, 16, 16, 9, 9, 10,
	8, 20, 20, 18, 18, 17, 17, 17, 19, 19,
	19, 21, 21, 21, 22, 22, 23, 23, 24, 24,
	25, 27, 27, 29, 29, 28, 28, 30, 30, 33,
	33, 32, 32, 34, 34, 34, 31, 31, 26, 26,
	26, 26, 26, 26, 26, 26,
}
var yyR2 = [...]int{

	0, 2, 2, 2, 4, 0, 2, 1, 5, 1,
	1, 2, 3, 3, 3, 4, 5, 7, 10, 7,
	6, 8, 1, 3, 3, 1, 3, 1, 3, 1,
	3, 1, 1, 1, 1, 3, 2, 1, 3, 2,
	12, 0, 1, 1, 3, 2, 5, 5, 1, 3,
	5, 1, 4, 3, 1, 3, 0, 1, 1, 2,
	5, 0, 2, 0, 3, 0, 2, 0, 2, 0,
	3, 2, 4, 0, 1, 1, 0, 2, 1, 1,
	2, 3, 3, 3, 3, 4,
}
var yyChk = [...]int{

	-1000, -1, -35, 54, -2, -4, -8, -5, 19, 25,
	-6, -7, 4, 5, 14, 22, -35, -35, 54, -35,
	20, -20, 26, 6, 11, 12, 6, 7, 11, 23,
	-35, -35, -18, -17, -19, 50, 44, 44, 44, 13,
	44, 8, 9, 44, -22, 44, -2, -3, -5, 27,
	52, -31, 37, 55, 53, 55, 44, 47, 10, 15,
	55, 53, 21, -35, 54, -21, -22, 55, -17, 44,
	58, -19, 44, -9, -10, 44, 55, 9, 47, 16,
	-11, 44, 44, -3, -23, -24, -25, 41, -22, -8,
	56, 56, 53, 52, 45, 44, 10, -10, 56, 52,
	-27, 30, -24, 28, -31, 56, -31, -31, 44, 17,
	-10, 56, 47, 24, 44, -29, 31, -26, -19, -16,
	38, 55, 40, 44, 46, 47, 48, 49, 57, -21,
	56, 18, -13, -14, 55, -28, 29, 32, 42, 43,
	39, -26, -26, 55, 55, 44, 13, 44, 52, -15,
	-16, 44, -30, 33, -26, -12, -19, -26, -26, 47,
	56, -8, 56, -26, 56, -14, 56, 52, -33, 34,
	46, 52, 56, -16, -31, 32, -19, -32, -19, 52,
	-34, 35, 36, -19, -34,
}
var yyDef = [...]int{

	5, -2, 0, 5, 1, 5, 5, 7, 0, 41,
	9, 10, 0, 0, 0, 0, 6, 2, 5, 3,
	5, 0, 42, 0, 0, 0, 0, 0, 0, 0,
	6, 0, 0, 43, 76, 0, 48, 13, 0, 0,
	14, 0, 0, 0, 0, 54, 4, 0, 5, 0,
	0, 45, 0, 0, 0, 0, 0, 15, 0, 0,
	0, 0, 8, 11, 5, 56, 51, 0, 44, 77,
	0, 0, 49, 0, 37, 0, 0, 0, 16, 0,
	0, 25, 55, 12, 61, 57, 58, 0, 76, 0,
	76, 76, 0, 0, 39, 0, 0, 20, 0, 0,
	63, 0, 59, 0, 0, 53, 46, 47, 50, 0,
	38, 19, 17, 0, 26, 65, 0, 62, 78, 79,
	0, 0, 0, 48, 31, 32, 33, 34, 0, 0,
	52, 0, 21, 22, 0, 67, 0, 0, 0, 0,
	0, 80, 0, 0, 0, 36, 0, 0, 0, 0,
	29, 0, 69, 0, 66, 64, 27, 83, 84, 82,
	81, 0, 35, 60, 18, 23, 24, 0, 76, 0,
	68, 0, 85, 30, 40, 0, 28, 70, 73, 0,
	71, 74, 75, 73, 72,
}
var yyTok1 = [...]int{

	1, 3, 3, 3, 3, 3, 3, 3, 3, 3,
	3, 3, 3, 3, 3, 3, 3, 3, 3, 3,
	3, 3, 3, 3, 3, 3, 3, 3, 3, 3,
	3, 3, 3, 3, 3, 3, 3, 3, 3, 3,
	55, 56, 58, 3, 52, 3, 53, 3, 3, 3,
	3, 3, 3, 3, 3, 3, 3, 3, 3, 3,
	3, 3, 3, 3, 57,
}
var yyTok2 = [...]int{

	2, 3, 4, 5, 6, 7, 8, 9, 10, 11,
	12, 13, 14, 15, 16, 17, 18, 19, 20, 21,
	22, 23, 24, 25, 26, 27, 28, 29, 30, 31,
	32, 33, 34, 35, 36, 37, 38, 39, 40, 41,
	42, 43, 44, 45, 46, 47, 48, 49, 50, 51,
	54,
}
var yyTok3 = [...]int{
	0,
}

var yyErrorMessages = [...]struct {
	state int
	token int
	msg   string
}{}

/*	parser for yacc output	*/

var (
	yyDebug        = 0
	yyErrorVerbose = false
)

type yyLexer interface {
	Lex(lval *yySymType) int
	Error(s string)
}

type yyParser interface {
	Parse(yyLexer) int
	Lookahead() int
}

type yyParserImpl struct {
	lval  yySymType
	stack [yyInitialStackSize]yySymType
	char  int
}

func (p *yyParserImpl) Lookahead() int {
	return p.char
}

func yyNewParser() yyParser {
	return &yyParserImpl{}
}

const yyFlag = -1000

func yyTokname(c int) string {
	if c >= 1 && c-1 < len(yyToknames) {
		if yyToknames[c-1] != "" {
			return yyToknames[c-1]
		}
	}
	return __yyfmt__.Sprintf("tok-%v", c)
}

func yyStatname(s int) string {
	if s >= 0 && s < len(yyStatenames) {
		if yyStatenames[s] != "" {
			return yyStatenames[s]
		}
	}
	return __yyfmt__.Sprintf("state-%v", s)
}

func yyErrorMessage(state, lookAhead int) string {
	const TOKSTART = 4

	if !yyErrorVerbose {
		return "syntax error"
	}

	for _, e := range yyErrorMessages {
		if e.state == state && e.token == lookAhead {
			return "syntax error: " + e.msg
		}
	}

	res := "syntax error: unexpected " + yyTokname(lookAhead)

	// To match Bison, suggest at most four expected tokens.
	expected := make([]int, 0, 4)

	// Look for shiftable tokens.
	base := yyPact[state]
	for tok := TOKSTART; tok-1 < len(yyToknames); tok++ {
		if n := base + tok; n >= 0 && n < yyLast && yyChk[yyAct[n]] == tok {
			if len(expected) == cap(expected) {
				return res
			}
			expected = append(expected, tok)
		}
	}

	if yyDef[state] == -2 {
		i := 0
		for yyExca[i] != -1 || yyExca[i+1] != state {
			i += 2
		}

		// Look for tokens that we accept or reduce.
		for i += 2; yyExca[i] >= 0; i += 2 {
			tok := yyExca[i]
			if tok < TOKSTART || yyExca[i+1] == 0 {
				continue
			}
			if len(expected) == cap(expected) {
				return res
			}
			expected = append(expected, tok)
		}

		// If the default action is to accept or reduce, give up.
		if yyExca[i+1] != 0 {
			return res
		}
	}

	for i, tok := range expected {
		if i == 0 {
			res += ", expecting "
		} else {
			res += " or "
		}
		res += yyTokname(tok)
	}
	return res
}

func yylex1(lex yyLexer, lval *yySymType) (char, token int) {
	token = 0
	char = lex.Lex(lval)
	if char <= 0 {
		token = yyTok1[0]
		goto out
	}
	if char < len(yyTok1) {
		token = yyTok1[char]
		goto out
	}
	if char >= yyPrivate {
		if char < yyPrivate+len(yyTok2) {
			token = yyTok2[char-yyPrivate]
			goto out
		}
	}
	for i := 0; i < len(yyTok3); i += 2 {
		token = yyTok3[i+0]
		if token == char {
			token = yyTok3[i+1]
			goto out
		}
	}

out:
	if token == 0 {
		token = yyTok2[1] /* unknown char */
	}
	if yyDebug >= 3 {
		__yyfmt__.Printf("lex %s(%d)\n", yyTokname(token), uint(char))
	}
	return char, token
}

func yyParse(yylex yyLexer) int {
	return yyNewParser().Parse(yylex)
}

func (yyrcvr *yyParserImpl) Parse(yylex yyLexer) int {
	var yyn int
	var yyVAL yySymType
	var yyDollar []yySymType
	_ = yyDollar // silence set and not used
	yyS := yyrcvr.stack[:]

	Nerrs := 0   /* number of errors */
	Errflag := 0 /* error recovery flag */
	yystate := 0
	yyrcvr.char = -1
	yytoken := -1 // yyrcvr.char translated into internal numbering
	defer func() {
		// Make sure we report no lookahead when not parsing.
		yystate = -1
		yyrcvr.char = -1
		yytoken = -1
	}()
	yyp := -1
	goto yystack

ret0:
	return 0

ret1:
	return 1

yystack:
	/* put a state and value onto the stack */
	if yyDebug >= 4 {
		__yyfmt__.Printf("char %v in %v\n", yyTokname(yytoken), yyStatname(yystate))
	}

	yyp++
	if yyp >= len(yyS) {
		nyys := make([]yySymType, len(yyS)*2)
		copy(nyys, yyS)
		yyS = nyys
	}
	yyS[yyp] = yyVAL
	yyS[yyp].yys = yystate

yynewstate:
	yyn = yyPact[yystate]
	if yyn <= yyFlag {
		goto yydefault /* simple state */
	}
	if yyrcvr.char < 0 {
		yyrcvr.char, yytoken = yylex1(yylex, &yyrcvr.lval)
	}
	yyn += yytoken
	if yyn < 0 || yyn >= yyLast {
		goto yydefault
	}
	yyn = yyAct[yyn]
	if yyChk[yyn] == yytoken { /* valid shift */
		yyrcvr.char = -1
		yytoken = -1
		yyVAL = yyrcvr.lval
		yystate = yyn
		if Errflag > 0 {
			Errflag--
		}
		goto yystack
	}

yydefault:
	/* default state action */
	yyn = yyDef[yystate]
	if yyn == -2 {
		if yyrcvr.char < 0 {
			yyrcvr.char, yytoken = yylex1(yylex, &yyrcvr.lval)
		}

		/* look through exception table */
		xi := 0
		for {
			if yyExca[xi+0] == -1 && yyExca[xi+1] == yystate {
				break
			}
			xi += 2
		}
		for xi += 2; ; xi += 2 {
			yyn = yyExca[xi+0]
			if yyn < 0 || yyn == yytoken {
				break
			}
		}
		yyn = yyExca[xi+1]
		if yyn < 0 {
			goto ret0
		}
	}
	if yyn == 0 {
		/* error ... attempt to resume parsing */
		switch Errflag {
		case 0: /* brand new error */
			yylex.Error(yyErrorMessage(yystate, yytoken))
			Nerrs++
			if yyDebug >= 1 {
				__yyfmt__.Printf("%s", yyStatname(yystate))
				__yyfmt__.Printf(" saw %s\n", yyTokname(yytoken))
			}
			fallthrough

		case 1, 2: /* incompletely recovered error ... try again */
			Errflag = 3

			/* find a state where "error" is a legal shift action */
			for yyp >= 0 {
				yyn = yyPact[yyS[yyp].yys] + yyErrCode
				if yyn >= 0 && yyn < yyLast {
					yystate = yyAct[yyn] /* simulate a shift of "error" */
					if yyChk[yystate] == yyErrCode {
						goto yystack
					}
				}

				/* the current p has no shift on "error", pop stack */
				if yyDebug >= 2 {
					__yyfmt__.Printf("error recovery pops state %d\n", yyS[yyp].yys)
				}
				yyp--
			}
			/* there is no state on the stack with an error shift ... abort */
			goto ret1

		case 3: /* no shift yet; clobber input char */
			if yyDebug >= 2 {
				__yyfmt__.Printf("error recovery discards %s\n", yyTokname(yytoken))
			}
			if yytoken == yyEofCode {
				goto ret1
			}
			yyrcvr.char = -1
			yytoken = -1
			goto yynewstate /* try again in the same state */
		}
	}

	/* reduction by production yyn */
	if yyDebug >= 2 {
		__yyfmt__.Printf("reduce %v in:\n\t%v\n", yyn, yyStatname(yystate))
	}

	yynt := yyn
	yypt := yyp
	_ = yypt // guard against "declared and not used"

	yyp -= yyR2[yyn]
	// yyp is now the index of $0. Perform the default action. Iff the
	// reduced production is ε, $1 is possibly out of range.
	if yyp+1 >= len(yyS) {
		nyys := make([]yySymType, len(yyS)*2)
		copy(nyys, yyS)
		yyS = nyys
	}
	yyVAL = yyS[yyp+1]

	/* consult goto table to find next state */
	yyn = yyR1[yyn]
	yyg := yyPgo[yyn]
	yyj := yyg + yyS[yyp].yys + 1

	if yyj >= yyLast {
		yystate = yyAct[yyg]
	} else {
		yystate = yyAct[yyj]
		if yyChk[yystate] != -yyn {
			yystate = yyAct[yyg]
		}
	}
	// dummy call; replaced with literal code
	switch yynt {

	case 1:
		yyDollar = yyS[yypt-2 : yypt+1]
		{
			yyVAL.stmts = yyDollar[2].stmts
			setResult(yylex, yyDollar[2].stmts)
		}
	case 2:
		yyDollar = yyS[yypt-2 : yypt+1]
		{
			yyVAL.stmts = []SQLStmt{yyDollar[1].stmt}
		}
	case 3:
		yyDollar = yyS[yypt-2 : yypt+1]
		{
			yyVAL.stmts = []SQLStmt{yyDollar[1].stmt}
		}
	case 4:
		yyDollar = yyS[yypt-4 : yypt+1]
		{
			yyVAL.stmts = append([]SQLStmt{yyDollar[1].stmt}, yyDollar[4].stmts...)
		}
	case 5:
		yyDollar = yyS[yypt-0 : yypt+1]
		{
		}
	case 8:
		yyDollar = yyS[yypt-5 : yypt+1]
		{
			yyVAL.stmt = &TxStmt{stmts: yyDollar[4].stmts}
		}
	case 11:
		yyDollar = yyS[yypt-2 : yypt+1]
		{
			yyVAL.stmts = []SQLStmt{yyDollar[1].stmt}
		}
	case 12:
		yyDollar = yyS[yypt-3 : yypt+1]
		{
			yyVAL.stmts = append([]SQLStmt{yyDollar[1].stmt}, yyDollar[3].stmts...)
		}
	case 13:
		yyDollar = yyS[yypt-3 : yypt+1]
		{
			yyVAL.stmt = &CreateDatabaseStmt{db: yyDollar[3].id}
		}
	case 14:
		yyDollar = yyS[yypt-3 : yypt+1]
		{
			yyVAL.stmt = &UseDatabaseStmt{db: yyDollar[3].id}
		}
	case 15:
		yyDollar = yyS[yypt-4 : yypt+1]
		{
			yyVAL.stmt = &UseSnapshotStmt{since: yyDollar[4].str}
		}
	case 16:
		yyDollar = yyS[yypt-5 : yypt+1]
		{
			yyVAL.stmt = &UseSnapshotStmt{upTo: yyDollar[5].str}
		}
	case 17:
		yyDollar = yyS[yypt-7 : yypt+1]
		{
			yyVAL.stmt = &UseSnapshotStmt{since: yyDollar[4].str, upTo: yyDollar[7].str}
		}
	case 18:
		yyDollar = yyS[yypt-10 : yypt+1]
		{
			yyVAL.stmt = &CreateTableStmt{table: yyDollar[3].id, colsSpec: yyDollar[5].colsSpec, pk: yyDollar[9].id}
		}
	case 19:
		yyDollar = yyS[yypt-7 : yypt+1]
		{
			yyVAL.stmt = &CreateIndexStmt{table: yyDollar[4].id, col: yyDollar[6].id}
		}
	case 20:
		yyDollar = yyS[yypt-6 : yypt+1]
		{
			yyVAL.stmt = &AddColumnStmt{table: yyDollar[3].id, colSpec: yyDollar[6].colSpec}
		}
	case 21:
		yyDollar = yyS[yypt-8 : yypt+1]
		{
			yyVAL.stmt = &UpsertIntoStmt{tableRef: yyDollar[3].tableRef, cols: yyDollar[5].ids, rows: yyDollar[8].rows}
		}
	case 22:
		yyDollar = yyS[yypt-1 : yypt+1]
		{
			yyVAL.rows = []*RowSpec{yyDollar[1].row}
		}
	case 23:
		yyDollar = yyS[yypt-3 : yypt+1]
		{
			yyVAL.rows = append(yyDollar[1].rows, yyDollar[3].row)
		}
	case 24:
		yyDollar = yyS[yypt-3 : yypt+1]
		{
			yyVAL.row = &RowSpec{Values: yyDollar[2].values}
		}
	case 25:
		yyDollar = yyS[yypt-1 : yypt+1]
		{
			yyVAL.ids = []string{yyDollar[1].id}
		}
	case 26:
		yyDollar = yyS[yypt-3 : yypt+1]
		{
			yyVAL.ids = append(yyDollar[1].ids, yyDollar[3].id)
		}
	case 27:
		yyDollar = yyS[yypt-1 : yypt+1]
		{
			yyVAL.cols = []*ColSelector{yyDollar[1].col}
		}
	case 28:
		yyDollar = yyS[yypt-3 : yypt+1]
		{
			yyVAL.cols = append(yyDollar[1].cols, yyDollar[3].col)
		}
	case 29:
		yyDollar = yyS[yypt-1 : yypt+1]
		{
			yyVAL.values = []Value{yyDollar[1].value}
		}
	case 30:
		yyDollar = yyS[yypt-3 : yypt+1]
		{
			yyVAL.values = append(yyDollar[1].values, yyDollar[3].value)
		}
	case 31:
		yyDollar = yyS[yypt-1 : yypt+1]
		{
			yyVAL.value = &Number{val: yyDollar[1].number}
		}
	case 32:
		yyDollar = yyS[yypt-1 : yypt+1]
		{
			yyVAL.value = &String{val: yyDollar[1].str}
		}
	case 33:
		yyDollar = yyS[yypt-1 : yypt+1]
		{
			yyVAL.value = &Bool{val: yyDollar[1].boolean}
		}
	case 34:
		yyDollar = yyS[yypt-1 : yypt+1]
		{
			yyVAL.value = &Blob{val: yyDollar[1].blob}
		}
	case 35:
		yyDollar = yyS[yypt-3 : yypt+1]
		{
			yyVAL.value = &SysFn{fn: yyDollar[1].id}
		}
	case 36:
		yyDollar = yyS[yypt-2 : yypt+1]
		{
			yyVAL.value = &Param{id: yyDollar[2].id}
		}
	case 37:
		yyDollar = yyS[yypt-1 : yypt+1]
		{
			yyVAL.colsSpec = []*ColSpec{yyDollar[1].colSpec}
		}
	case 38:
		yyDollar = yyS[yypt-3 : yypt+1]
		{
			yyVAL.colsSpec = append(yyDollar[1].colsSpec, yyDollar[3].colSpec)
		}
	case 39:
		yyDollar = yyS[yypt-2 : yypt+1]
		{
			yyVAL.colSpec = &ColSpec{colName: yyDollar[1].id, colType: yyDollar[2].sqlType}
		}
	case 40:
		yyDollar = yyS[yypt-12 : yypt+1]
		{
			yyVAL.stmt = &SelectStmt{
				distinct:  yyDollar[2].distinct,
				selectors: yyDollar[3].sels,
				ds:        yyDollar[5].ds,
				joins:     yyDollar[6].joins,
				where:     yyDollar[7].boolExp,
				groupBy:   yyDollar[8].cols,
				having:    yyDollar[9].boolExp,
				limit:     yyDollar[10].number,
				orderBy:   yyDollar[11].ordcols,
				as:        yyDollar[12].id,
			}
		}
	case 41:
		yyDollar = yyS[yypt-0 : yypt+1]
		{
			yyVAL.distinct = false
		}
	case 42:
		yyDollar = yyS[yypt-1 : yypt+1]
		{
			yyVAL.distinct = true
		}
	case 43:
		yyDollar = yyS[yypt-1 : yypt+1]
		{
			yyVAL.sels = []Selector{yyDollar[1].sel}
		}
	case 44:
		yyDollar = yyS[yypt-3 : yypt+1]
		{
			yyVAL.sels = append(yyDollar[1].sels, yyDollar[3].sel)
		}
	case 45:
		yyDollar = yyS[yypt-2 : yypt+1]
		{
			yyDollar[1].col.as = yyDollar[2].id
			yyVAL.sel = yyDollar[1].col
		}
	case 46:
		yyDollar = yyS[yypt-5 : yypt+1]
		{
			yyVAL.sel = &AggColSelector{aggFn: yyDollar[1].aggFn, as: yyDollar[5].id}
		}
	case 47:
		yyDollar = yyS[yypt-5 : yypt+1]
		{
			yyVAL.sel = &AggColSelector{aggFn: yyDollar[1].aggFn, db: yyDollar[3].col.db, table: yyDollar[3].col.table, col: yyDollar[3].col.col, as: yyDollar[5].id}
		}
	case 48:
		yyDollar = yyS[yypt-1 : yypt+1]
		{
			yyVAL.col = &ColSelector{col: yyDollar[1].id}
		}
	case 49:
		yyDollar = yyS[yypt-3 : yypt+1]
		{
			yyVAL.col = &ColSelector{table: yyDollar[1].id, col: yyDollar[3].id}
		}
	case 50:
		yyDollar = yyS[yypt-5 : yypt+1]
		{
			yyVAL.col = &ColSelector{db: yyDollar[1].id, table: yyDollar[3].id, col: yyDollar[5].id}
		}
	case 51:
		yyDollar = yyS[yypt-1 : yypt+1]
		{
			yyVAL.ds = yyDollar[1].tableRef
		}
	case 52:
		yyDollar = yyS[yypt-4 : yypt+1]
		{
			yyDollar[2].tableRef.as = yyDollar[3].id
			yyVAL.ds = yyDollar[2].tableRef
		}
	case 53:
		yyDollar = yyS[yypt-3 : yypt+1]
		{
			yyVAL.ds = yyDollar[2].stmt.(*SelectStmt)
		}
	case 54:
		yyDollar = yyS[yypt-1 : yypt+1]
		{
			yyVAL.tableRef = &TableRef{table: yyDollar[1].id}
		}
	case 55:
		yyDollar = yyS[yypt-3 : yypt+1]
		{
			yyVAL.tableRef = &TableRef{db: yyDollar[1].id, table: yyDollar[3].id}
		}
	case 56:
		yyDollar = yyS[yypt-0 : yypt+1]
		{
			yyVAL.joins = nil
		}
	case 57:
		yyDollar = yyS[yypt-1 : yypt+1]
		{
			yyVAL.joins = yyDollar[1].joins
		}
	case 58:
		yyDollar = yyS[yypt-1 : yypt+1]
		{
			yyVAL.joins = []*JoinSpec{yyDollar[1].join}
		}
	case 59:
		yyDollar = yyS[yypt-2 : yypt+1]
		{
			yyVAL.joins = append([]*JoinSpec{yyDollar[1].join}, yyDollar[2].joins...)
		}
	case 60:
		yyDollar = yyS[yypt-5 : yypt+1]
		{
			yyVAL.join = &JoinSpec{joinType: yyDollar[1].joinType, ds: yyDollar[3].ds, cond: yyDollar[5].boolExp}
		}
	case 61:
		yyDollar = yyS[yypt-0 : yypt+1]
		{
			yyVAL.boolExp = nil
		}
	case 62:
		yyDollar = yyS[yypt-2 : yypt+1]
		{
			yyVAL.boolExp = yyDollar[2].boolExp
		}
	case 63:
		yyDollar = yyS[yypt-0 : yypt+1]
		{
			yyVAL.cols = nil
		}
	case 64:
		yyDollar = yyS[yypt-3 : yypt+1]
		{
			yyVAL.cols = yyDollar[3].cols
		}
	case 65:
		yyDollar = yyS[yypt-0 : yypt+1]
		{
			yyVAL.boolExp = nil
		}
	case 66:
		yyDollar = yyS[yypt-2 : yypt+1]
		{
			yyVAL.boolExp = yyDollar[2].boolExp
		}
	case 67:
		yyDollar = yyS[yypt-0 : yypt+1]
		{
			yyVAL.number = 0
		}
	case 68:
		yyDollar = yyS[yypt-2 : yypt+1]
		{
			yyVAL.number = yyDollar[2].number
		}
	case 69:
		yyDollar = yyS[yypt-0 : yypt+1]
		{
			yyVAL.ordcols = nil
		}
	case 70:
		yyDollar = yyS[yypt-3 : yypt+1]
		{
			yyVAL.ordcols = yyDollar[3].ordcols
		}
	case 71:
		yyDollar = yyS[yypt-2 : yypt+1]
		{
			yyVAL.ordcols = []*OrdCol{{sel: yyDollar[1].col, cmp: yyDollar[2].opt_ord}}
		}
	case 72:
		yyDollar = yyS[yypt-4 : yypt+1]
		{
			yyVAL.ordcols = append(yyDollar[1].ordcols, &OrdCol{sel: yyDollar[3].col, cmp: yyDollar[4].opt_ord})
		}
	case 73:
		yyDollar = yyS[yypt-0 : yypt+1]
		{
			yyVAL.opt_ord = GreaterOrEqualTo
		}
	case 74:
		yyDollar = yyS[yypt-1 : yypt+1]
		{
			yyVAL.opt_ord = GreaterOrEqualTo
		}
	case 75:
		yyDollar = yyS[yypt-1 : yypt+1]
		{
			yyVAL.opt_ord = LowerOrEqualTo
		}
	case 76:
		yyDollar = yyS[yypt-0 : yypt+1]
		{
			yyVAL.id = ""
		}
	case 77:
		yyDollar = yyS[yypt-2 : yypt+1]
		{
			yyVAL.id = yyDollar[2].id
		}
	case 78:
		yyDollar = yyS[yypt-1 : yypt+1]
		{
			yyVAL.boolExp = yyDollar[1].col
		}
	case 79:
		yyDollar = yyS[yypt-1 : yypt+1]
		{
			yyVAL.boolExp = yyDollar[1].value
		}
	case 80:
		yyDollar = yyS[yypt-2 : yypt+1]
		{
			yyVAL.boolExp = &NotBoolExp{exp: yyDollar[2].boolExp}
		}
	case 81:
		yyDollar = yyS[yypt-3 : yypt+1]
		{
			yyVAL.boolExp = yyDollar[2].boolExp
		}
	case 82:
		yyDollar = yyS[yypt-3 : yypt+1]
		{
			yyVAL.boolExp = &LikeBoolExp{col: yyDollar[1].col, pattern: yyDollar[3].str}
		}
	case 83:
		yyDollar = yyS[yypt-3 : yypt+1]
		{
			yyVAL.boolExp = &BinBoolExp{op: yyDollar[2].logicOp, left: yyDollar[1].boolExp, right: yyDollar[3].boolExp}
		}
	case 84:
		yyDollar = yyS[yypt-3 : yypt+1]
		{
			yyVAL.boolExp = &CmpBoolExp{op: yyDollar[2].cmpOp, left: yyDollar[1].boolExp, right: yyDollar[3].boolExp}
		}
	case 85:
		yyDollar = yyS[yypt-4 : yypt+1]
		{
			yyVAL.boolExp = &ExistsBoolExp{q: (yyDollar[3].stmt).(*SelectStmt)}
		}
	}
	goto yystack /* stack new state and value */
}
