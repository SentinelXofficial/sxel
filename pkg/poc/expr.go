package poc

import (
	"fmt"
	"math"
	"regexp"
	"strconv"
	"strings"
	"time"
)

type evalCtx struct {
	set   map[string]string
	resp  *Response
	rules map[string]bool
}

type exprNode struct {
	kind  string
	text  string
	left  *exprNode
	right *exprNode
	args  []*exprNode
	path  []pathElem
}

type pathElem struct {
	typ  string // field | call | index
	name string
	args []*exprNode
	idx  *exprNode
}

type token struct {
	typ string
	val string
}

func tokenize(s string) ([]token, error) {
	var toks []token
	i := 0
	n := len(s)
	for i < n {
		c := s[i]
		switch {
		case c == ' ' || c == '\t' || c == '\n':
			i++
		case c == '(':
			toks = append(toks, token{"(", "("})
			i++
		case c == ')':
			toks = append(toks, token{")", ")"})
			i++
		case c == '.':
			toks = append(toks, token{".", "."})
			i++
		case c == ',':
			toks = append(toks, token{",", ","})
			i++
		case c == '[':
			toks = append(toks, token{"[", "["})
			i++
		case c == ']':
			toks = append(toks, token{"]", "]"})
			i++
		case c == '"' || c == '\'':
			q := c
			j := i + 1
			var sb strings.Builder
			for j < n && s[j] != q {
				if s[j] == '\\' && j+1 < n {
					switch s[j+1] {
					case 'n':
						sb.WriteByte('\n')
					case 't':
						sb.WriteByte('\t')
					case 'r':
						sb.WriteByte('\r')
					case '\\', '"', '\'':
						sb.WriteByte(s[j+1])
					default:
						sb.WriteByte(s[j])
						sb.WriteByte(s[j+1])
					}
					j += 2
					continue
				}
				sb.WriteByte(s[j])
				j++
			}
			toks = append(toks, token{"str", sb.String()})
			i = j + 1
		case c == '-':
			toks = append(toks, token{"-", "-"})
			i++
		case strings.HasPrefix(s[i:], "=="):
			toks = append(toks, token{"==", "=="})
			i += 2
		case strings.HasPrefix(s[i:], "!="):
			toks = append(toks, token{"!=", "!="})
			i += 2
		case strings.HasPrefix(s[i:], "&&"):
			toks = append(toks, token{"&&", "&&"})
			i += 2
		case strings.HasPrefix(s[i:], "||"):
			toks = append(toks, token{"||", "||"})
			i += 2
		case strings.HasPrefix(s[i:], ">="):
			toks = append(toks, token{">=", ">="})
			i += 2
		case strings.HasPrefix(s[i:], "<="):
			toks = append(toks, token{"<=", "<="})
			i += 2
		case c == '!':
			toks = append(toks, token{"!", "!"})
			i++
		case c == '>':
			toks = append(toks, token{">", ">"})
			i++
		case c == '<':
			toks = append(toks, token{"<", "<"})
			i++
		case c >= '0' && c <= '9' || (c == '.' && i+1 < n && s[i+1] >= '0' && s[i+1] <= '9'):
			j := i
			for j < n && (s[j] >= '0' && s[j] <= '9' || s[j] == '.') {
				j++
			}
			toks = append(toks, token{"num", s[i:j]})
			i = j
		case isIdentChar(c):
			j := i
			for j < n && isIdentChar(s[j]) {
				j++
			}
			toks = append(toks, token{"ident", s[i:j]})
			i = j
		default:
			return nil, fmt.Errorf("unexpected char %q", string(c))
		}
	}
	return toks, nil
}

func isIdentChar(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_'
}

type parser struct {
	toks []token
	pos  int
}

func (p *parser) peek() *token {
	if p.pos < len(p.toks) {
		return &p.toks[p.pos]
	}
	return nil
}

func (p *parser) next() *token {
	t := p.peek()
	if t != nil {
		p.pos++
	}
	return t
}

func parseExpr(src string) (*exprNode, error) {
	toks, err := tokenize(src)
	if err != nil {
		return nil, err
	}
	if len(toks) == 0 {
		return nil, fmt.Errorf("empty expression")
	}
	pr := &parser{toks: toks}
	node, err := pr.parseOr()
	if err != nil {
		return nil, err
	}
	if pr.peek() != nil {
		return nil, fmt.Errorf("unexpected token %q", pr.peek().val)
	}
	return node, nil
}

func (pr *parser) parseOr() (*exprNode, error) {
	left, err := pr.parseAnd()
	if err != nil {
		return nil, err
	}
	for pr.peek() != nil && pr.peek().typ == "||" {
		pr.next()
		right, err := pr.parseAnd()
		if err != nil {
			return nil, err
		}
		left = &exprNode{kind: "or", left: left, right: right}
	}
	return left, nil
}

func (pr *parser) parseAnd() (*exprNode, error) {
	left, err := pr.parseCmp()
	if err != nil {
		return nil, err
	}
	for pr.peek() != nil && pr.peek().typ == "&&" {
		pr.next()
		right, err := pr.parseCmp()
		if err != nil {
			return nil, err
		}
		left = &exprNode{kind: "and", left: left, right: right}
	}
	return left, nil
}

func (pr *parser) parseCmp() (*exprNode, error) {
	left, err := pr.parseSub()
	if err != nil {
		return nil, err
	}
	if pr.peek() != nil {
		switch pr.peek().typ {
		case "==", "!=", ">", "<", ">=", "<=":
			op := pr.next()
			right, err := pr.parseSub()
			if err != nil {
				return nil, err
			}
			left = &exprNode{kind: "cmp", text: op.typ, left: left, right: right}
		}
	}
	return left, nil
}

func (pr *parser) parseSub() (*exprNode, error) {
	left, err := pr.parseUnary()
	if err != nil {
		return nil, err
	}
	for pr.peek() != nil && pr.peek().typ == "-" {
		pr.next()
		right, err := pr.parseUnary()
		if err != nil {
			return nil, err
		}
		left = &exprNode{kind: "sub", left: left, right: right}
	}
	return left, nil
}

func (pr *parser) parseUnary() (*exprNode, error) {
	if pr.peek() != nil && pr.peek().typ == "!" {
		pr.next()
		n, err := pr.parseUnary()
		if err != nil {
			return nil, err
		}
		return &exprNode{kind: "not", left: n}, nil
	}
	if pr.peek() != nil && pr.peek().typ == "-" {
		pr.next()
		n, err := pr.parseUnary()
		if err != nil {
			return nil, err
		}
		return &exprNode{kind: "neg", left: n}, nil
	}
	return pr.parsePrimary()
}

func (pr *parser) parsePrimary() (*exprNode, error) {
	t := pr.next()
	if t == nil {
		return nil, fmt.Errorf("unexpected end of expression")
	}
	switch t.typ {
	case "(":
		n, err := pr.parseOr()
		if err != nil {
			return nil, err
		}
		if pr.next() == nil || pr.toks[pr.pos-1].typ != ")" {
			return nil, fmt.Errorf("missing closing paren")
		}
		return n, nil
	case "num":
		return &exprNode{kind: "num", text: t.val}, nil
	case "str":
		return &exprNode{kind: "str", text: t.val}, nil
	case "ident":
		return pr.parsePath(t.val)
	default:
		return nil, fmt.Errorf("unexpected token %q", t.val)
	}
}

func (pr *parser) parsePath(first string) (*exprNode, error) {
	node := &exprNode{kind: "path", path: []pathElem{{typ: "field", name: first}}}
	for {
		t := pr.peek()
		if t == nil {
			return node, nil
		}
		switch t.typ {
		case ".":
			pr.next()
			member := pr.next()
			if member == nil || member.typ != "ident" {
				return nil, fmt.Errorf("expected identifier after '.'")
			}
			if pr.peek() != nil && pr.peek().typ == "(" {
				pr.next()
				args, err := pr.parseArgs()
				if err != nil {
					return nil, err
				}
				node.path = append(node.path, pathElem{typ: "call", name: member.val, args: args})
			} else {
				node.path = append(node.path, pathElem{typ: "field", name: member.val})
			}
		case "(":
			if len(node.path) == 0 {
				return nil, fmt.Errorf("unexpected '('")
			}
			pr.next()
			args, err := pr.parseArgs()
			if err != nil {
				return nil, err
			}
			last := node.path[len(node.path)-1]
			last.typ = "call"
			last.args = args
			node.path[len(node.path)-1] = last
		case "[":
			pr.next()
			idx, err := pr.parseOr()
			if err != nil {
				return nil, err
			}
			if pr.next() == nil || pr.toks[pr.pos-1].typ != "]" {
				return nil, fmt.Errorf("missing closing bracket")
			}
			node.path = append(node.path, pathElem{typ: "index", idx: idx})
		default:
			return node, nil
		}
	}
}

func (pr *parser) parseArgs() ([]*exprNode, error) {
	var args []*exprNode
	if pr.peek() != nil && pr.peek().typ == ")" {
		pr.next()
		return args, nil
	}
	for {
		arg, err := pr.parseOr()
		if err != nil {
			return nil, err
		}
		args = append(args, arg)
		if pr.peek() != nil && pr.peek().typ == "," {
			pr.next()
			continue
		}
		if pr.next() == nil || pr.toks[pr.pos-1].typ != ")" {
			return nil, fmt.Errorf("missing closing paren in args")
		}
		return args, nil
	}
}

func (n *exprNode) eval(c evalCtx) (interface{}, error) {
	switch n.kind {
	case "num":
		f, err := strconv.ParseFloat(n.text, 64)
		if err != nil {
			return nil, err
		}
		return f, nil
	case "str":
		return n.text, nil
	case "or":
		l, err := n.left.eval(c)
		if err != nil {
			return nil, err
		}
		if toBool(l) {
			return true, nil
		}
		r, err := n.right.eval(c)
		return toBool(r), err
	case "and":
		l, err := n.left.eval(c)
		if err != nil {
			return nil, err
		}
		if !toBool(l) {
			return false, nil
		}
		r, err := n.right.eval(c)
		return toBool(r), err
	case "not":
		v, err := n.left.eval(c)
		if err != nil {
			return nil, err
		}
		return !toBool(v), nil
	case "neg":
		v, err := n.left.eval(c)
		if err != nil {
			return nil, err
		}
		f, ok := toNum(v)
		if !ok {
			return nil, fmt.Errorf("cannot negate %v", v)
		}
		return -f, nil
	case "sub":
		l, err := n.left.eval(c)
		if err != nil {
			return nil, err
		}
		r, err := n.right.eval(c)
		if err != nil {
			return nil, err
		}
		lf, lok := toNum(l)
		rf, rok := toNum(r)
		if lok && rok {
			return lf - rf, nil
		}
		return nil, fmt.Errorf("cannot subtract %v - %v", l, r)
	case "cmp":
		return n.evalCmp(c)
	case "path":
		return n.evalPath(c)
	}
	return nil, fmt.Errorf("unknown node %q", n.kind)
}

func (n *exprNode) evalCmp(c evalCtx) (interface{}, error) {
	l, err := n.left.eval(c)
	if err != nil {
		return nil, err
	}
	r, err := n.right.eval(c)
	if err != nil {
		return nil, err
	}
	lf, lIsNum := toNum(l)
	rf, rIsNum := toNum(r)
	if lIsNum && rIsNum {
		switch n.text {
		case "==":
			return lf == rf, nil
		case "!=":
			return lf != rf, nil
		case ">":
			return lf > rf, nil
		case "<":
			return lf < rf, nil
		case ">=":
			return lf >= rf, nil
		case "<=":
			return lf <= rf, nil
		}
	}
	ls := toStr(l)
	rs := toStr(r)
	switch n.text {
	case "==":
		return ls == rs, nil
	case "!=":
		return ls != rs, nil
	case ">":
		return ls > rs, nil
	case "<":
		return ls < rs, nil
	case ">=":
		return ls >= rs, nil
	case "<=":
		return ls <= rs, nil
	}
	return false, nil
}

func (n *exprNode) evalPath(c evalCtx) (interface{}, error) {
	var val interface{}
	first := n.path[0]
	if first.typ == "call" {
		var args []interface{}
		for _, a := range first.args {
			av, err := a.eval(c)
			if err != nil {
				return nil, err
			}
			args = append(args, av)
		}
		if first.name == "randomInt" || first.name == "randomIntn" || first.name == "randomLowercase" ||
			first.name == "randomUppercase" || first.name == "randomAlpha" || first.name == "randomAlphaN" {
			return setFn(first.name, args)
		}
		if hf, ok := hashFns[first.name]; ok {
			if len(args) == 0 {
				return "", fmt.Errorf("%s() requires an argument", first.name)
			}
			return hf(toStr(args[0])), nil
		}
		if b, ok := c.rules[first.name]; ok {
			return b, nil
		}
		return nil, fmt.Errorf("unknown function %q", first.name)
	}
	if first.name == "response" {
		if c.resp == nil {
			return nil, fmt.Errorf("response not available")
		}
		val = respObj(c.resp)
	} else if first.name == "response_1" || first.name == "response_2" {
		if c.resp == nil {
			return nil, fmt.Errorf("response not available")
		}
		val = respObj(c.resp)
	} else if v, ok := c.set[first.name]; ok {
		val = v
	} else if b, ok := c.rules[first.name]; ok {
		val = b
	} else {
		return nil, fmt.Errorf("unknown identifier %q", first.name)
	}
	for _, el := range n.path[1:] {
		switch el.typ {
		case "field":
			val = getField(val, el.name, c)
		case "index":
			k, err := el.idx.eval(c)
			if err != nil {
				return nil, err
			}
			val = getIndex(val, toStr(k))
		case "call":
			fn := el.name
			recv := val
			var args []interface{}
			for _, a := range el.args {
				av, err := a.eval(c)
				if err != nil {
					return nil, err
				}
				args = append(args, av)
			}
			rv, cerr := callMethod(recv, fn, args)
			if cerr != nil {
				return nil, cerr
			}
			val = rv
		}
	}
	return val, nil
}

func respObj(r *Response) map[string]interface{} {
	return map[string]interface{}{
		"status":       float64(r.Status),
		"body":         r.Body,
		"headers":      r.Headers,
		"content_type": r.ContentType,
		"latency":      float64(r.LatencyMs),
	}
}

func getField(v interface{}, name string, c evalCtx) interface{} {
	switch t := v.(type) {
	case map[string]interface{}:
		if f, ok := t[name]; ok {
			return f
		}
	case map[string]string:
		if f, ok := t[name]; ok {
			return f
		}
	}
	return ""
}

func getIndex(v interface{}, key string) interface{} {
	switch t := v.(type) {
	case map[string][]string:
		if vals, ok := t[key]; ok && len(vals) > 0 {
			return vals[0]
		}
	case map[string]interface{}:
		if f, ok := t[key]; ok {
			return f
		}
	case map[string]string:
		if f, ok := t[key]; ok {
			return f
		}
	}
	return ""
}

func callMethod(recv interface{}, fn string, args []interface{}) (interface{}, error) {
	s := toStr(recv)
	switch fn {
	case "contains":
		if len(args) < 1 {
			return false, nil
		}
		return strings.Contains(s, toStr(args[0])), nil
	case "bcontains":
		if len(args) < 1 {
			return false, nil
		}
		return strings.Contains(s, toStr(args[0])), nil
	case "matches", "bmatches":
		if len(args) < 1 {
			return false, nil
		}
		re, err := regexp.Compile(toStr(args[0]))
		if err != nil {
			return false, nil
		}
		return re.MatchString(s), nil
	case "indexOf":
		if len(args) < 1 {
			return float64(-1), nil
		}
		return float64(strings.Index(s, toStr(args[0]))), nil
	case "length":
		return float64(len(s)), nil
	case "tolower":
		return strings.ToLower(s), nil
	case "toupper":
		return strings.ToUpper(s), nil
	case "replace":
		if len(args) < 2 {
			return s, nil
		}
		return strings.ReplaceAll(s, toStr(args[0]), toStr(args[1])), nil
	case "startswith":
		if len(args) < 1 {
			return false, nil
		}
		return strings.HasPrefix(s, toStr(args[0])), nil
	case "endswith":
		if len(args) < 1 {
			return false, nil
		}
		return strings.HasSuffix(s, toStr(args[0])), nil
	case "md5", "sha1", "sha256", "base64", "base64encode", "urlencode":
		if fn, ok := hashFns[fn]; ok {
			return fn(s), nil
		}
	}
	if fn == "randomInt" || fn == "randomIntn" || fn == "randomLowercase" ||
		fn == "randomUppercase" || fn == "randomAlpha" || fn == "randomAlphaN" {
		return setFn(fn, args)
	}
	return "", nil
}

func setFn(fn string, args []interface{}) (interface{}, error) {
	switch fn {
	case "randomInt":
		lo := 0
		hi := 9999
		if len(args) >= 2 {
			lo = int(toNumVal(args[0]))
			hi = int(toNumVal(args[1]))
		}
		if hi <= lo {
			hi = lo + 1
		}
		return float64(rndIntRange(lo, hi)), nil
	case "randomIntn":
		n := 100
		if len(args) >= 1 {
			n = int(toNumVal(args[0]))
		}
		return float64(rndIntn(max(n, 1))), nil
	case "randomLowercase":
		return randomString("abcdefghijklmnopqrstuvwxyz", argLen(args)), nil
	case "randomUppercase":
		return randomString("ABCDEFGHIJKLMNOPQRSTUVWXYZ", argLen(args)), nil
	case "randomAlpha":
		return randomString("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ", argLen(args)), nil
	case "randomAlphaN":
		return randomString("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789", argLen(args)), nil
	}
	return "", nil
}

func randomString(chars string, n int) string {
	if n <= 0 {
		n = 8
	}
	return rndBytes(chars, n)
}

func argLen(args []interface{}) int {
	if len(args) >= 1 {
		return int(toNumVal(args[0]))
	}
	return 8
}

func toNumVal(v interface{}) float64 {
	f, _ := toNum(v)
	return f
}

func toNum(v interface{}) (float64, bool) {
	switch t := v.(type) {
	case float64:
		return t, true
	case int:
		return float64(t), true
	case int64:
		return float64(t), true
	case bool:
		if t {
			return 1, true
		}
		return 0, true
	case string:
		f, err := strconv.ParseFloat(strings.TrimSpace(t), 64)
		if err == nil {
			return f, true
		}
	}
	return 0, false
}

func toBool(v interface{}) bool {
	if v == nil {
		return false
	}
	switch t := v.(type) {
	case bool:
		return t
	case float64:
		return t != 0
	case int:
		return t != 0
	case string:
		switch strings.ToLower(strings.TrimSpace(t)) {
		case "", "false", "0", "no", "off", "null", "nil", "none":
			return false
		}
		return true
	}
	return false
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func evalBool(src string, c evalCtx) (bool, error) {
	node, err := parseExpr(src)
	if err != nil {
		return false, err
	}
	v, err := node.eval(c)
	if err != nil {
		return false, err
	}
	return toBool(v), nil
}

var _ = math.Pi
var _ = time.Now
