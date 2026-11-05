package usagetransport

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/ElXnet/ElX-control/internal/elxcontrol/accounting"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

// DiscoverBindings obtains current usage assignments from the authoritative
// master over the already authenticated node mTLS channel. Re-reading this
// list every polling interval picks up newly provisioned streams and removes
// revoked/expired assignments without editing a file on each VPN node.
func DiscoverBindings(ctx context.Context,conn grpc.ClientConnInterface)([]accounting.RemoteBinding,error){
	if conn==nil{return nil,errors.New("usage assignment discovery requires Control")}
	var response wrapperspb.BytesValue
	if err:=conn.Invoke(ctx,"/"+serviceName+"/Bindings",&emptypb.Empty{},&response,
		grpc.MaxCallRecvMsgSize(1<<20));err!=nil{return nil,err}
	if len(response.Value)>1<<20{return nil,errors.New("usage assignment response exceeds limit")}
	var bindings []accounting.RemoteBinding
	if err:=json.Unmarshal(response.Value,&bindings);err!=nil{
		return nil,errors.New("invalid Control usage assignment list")
	}
	if len(bindings)>1000{return nil,errors.New("too many Control usage assignments")}
	seen:=make(map[accounting.RemoteBinding]bool,len(bindings))
	for _,b:=range bindings{
		if !b.Valid()||seen[b]{return nil,errors.New("invalid or duplicate Control usage assignment")}
		seen[b]=true
	}
	return bindings,nil
}
