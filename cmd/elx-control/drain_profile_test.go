package main

import (
	"testing"

	"github.com/google/uuid"
)

func TestDrainProfileRequiresProvisionedCanonicalGeneration(t *testing.T) {
	ids:=[]string{uuid.NewString(),uuid.NewString(),uuid.NewString(),uuid.NewString()}
	valid:=[]string{"-owner",ids[0],"-profile",ids[1],"-node",ids[2],
		"-incarnation",ids[3],"-generation","6"}
	got,err:=parseDrainProfile(valid)
	if err!=nil || got.OwnerID.String()!=ids[0] ||
		got.ProfileID.String()!=ids[1] || got.Generation!=6 {
		t.Fatalf("valid fence arguments rejected: %+v %v",got,err)
	}
	for _,args:=range [][]string{
		nil,{"-owner",ids[0]},append(append([]string{},valid...),"extra"),
		{"-owner",uuid.Nil.String(),"-profile",ids[1],"-node",ids[2],
			"-incarnation",ids[3],"-generation","6"},
		{"-owner",ids[0],"-profile",ids[1],"-node",ids[2],
			"-incarnation",ids[3],"-generation","0"},
	} {
		if _,err:=parseDrainProfile(args);err==nil {t.Fatalf("unsafe profile fence parsed: %v",args)}
	}
}
