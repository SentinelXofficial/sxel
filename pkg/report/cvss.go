package report

import (
	"fmt"
	"strings"
)

type Vector struct {
	AV string
	AC string
	PR string
	UI string
	S  string
	C  string
	I  string
	A  string
}

func (v Vector) String() string {
	return fmt.Sprintf("CVSS:3.1/AV:%s/AC:%s/PR:%s/UI:%s/S:%s/C:%s/I:%s/A:%s",
		v.AV, v.AC, v.PR, v.UI, v.S, v.C, v.I, v.A)
}

func BaseVector(severity, vulnType string) string {
	lower := strings.ToLower(vulnType)
	persistent := strings.Contains(lower, "stored") ||
		strings.Contains(lower, "second-order") ||
		strings.Contains(lower, "persistent")
	ui := "N"
	sScope := "U"
	if persistent {
		ui = "R"
		sScope = "C"
	}
	switch strings.ToUpper(severity) {
	case "CRITICAL":
		return Vector{"N", "L", "N", ui, sScope, "H", "H", "H"}.String()
	case "HIGH":
		if persistent {
			return Vector{"N", "L", "N", "R", "C", "H", "H", "L"}.String()
		}
		return Vector{"N", "L", "N", "N", "U", "H", "L", "N"}.String()
	case "MEDIUM":
		if persistent {
			return Vector{"N", "L", "N", "R", "C", "L", "L", "N"}.String()
		}
		return Vector{"N", "L", "N", "N", "U", "L", "L", "N"}.String()
	case "LOW":
		return Vector{"N", "L", "N", "N", "U", "L", "N", "N"}.String()
	}
	return Vector{"N", "L", "N", "N", "U", "N", "N", "N"}.String()
}

var cvssAV = map[string]float64{"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
var cvssAC = map[string]float64{"L": 0.77, "H": 0.44}
var cvssUI = map[string]float64{"N": 0.85, "R": 0.62}

func CVSS3Score(vector string) float64 {
	vals := map[string]string{}
	for _, part := range strings.Split(vector, "/") {
		kv := strings.SplitN(part, ":", 2)
		if len(kv) == 2 {
			vals[kv[0]] = kv[1]
		}
	}
	av := cvssAV[vals["AV"]]
	ac := cvssAC[vals["AC"]]
	ui := cvssUI[vals["UI"]]
	pr := 0.85
	switch vals["PR"] {
	case "L":
		if vals["S"] == "C" {
			pr = 0.68
		} else {
			pr = 0.62
		}
	case "H":
		if vals["S"] == "C" {
			pr = 0.5
		} else {
			pr = 0.27
		}
	}
	c := cvssCIa(vals["C"])
	i := cvssCIa(vals["I"])
	a := cvssCIa(vals["A"])

	iss := 1 - (1-c)*(1-i)*(1-a)
	var impact float64
	if vals["S"] == "C" {
		impact = 7.52*(iss-0.029) - 3.25*pow15(iss-0.02)
	} else {
		impact = 6.42 * iss
	}
	if impact <= 0 {
		return 0
	}
	exploit := 8.22 * av * ac * pr * ui
	var score float64
	if vals["S"] == "C" {
		score = 1.08 * (impact + exploit)
	} else {
		score = impact + exploit
	}
	if score > 10 {
		score = 10
	}
	return roundup1(score)
}

func cvssCIa(v string) float64 {
	switch v {
	case "H":
		return 0.56
	case "L":
		return 0.22
	}
	return 0
}

func pow15(x float64) float64 {
	r := x
	for i := 0; i < 14; i++ {
		r *= x
	}
	return r
}

func roundup1(x float64) float64 {
	ceil := int(x*10 + 0.999999)
	return float64(ceil) / 10
}

func SeverityFromScore(score float64) string {
	switch {
	case score >= 9:
		return "CRITICAL"
	case score >= 7:
		return "HIGH"
	case score >= 4:
		return "MEDIUM"
	case score > 0:
		return "LOW"
	}
	return "INFO"
}
