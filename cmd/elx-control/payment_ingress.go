package main

import (
 "context"
 "database/sql"
 "errors"
 "net"
 "net/http"
 "os"
 "path/filepath"
 "strconv"
 "strings"
 "time"

 "github.com/ElXnet/ElX-control/internal/elxcontrol/billing"
)

// servePaymentIngress is a separate process with a separate 0600 Unix socket.
// The independent payment checker has access only to this socket, NEVER the
// administrative Control socket or bank credentials in Control.
func servePaymentIngress(ctx context.Context,db *sql.DB)error{
 path:=os.Getenv("ELX_PAYMENT_SOCKET")
 if path==""||!filepath.IsAbs(path)||path=="/"{
  return errors.New("ELX_PAYMENT_SOCKET must be an absolute Unix socket path")
 }
 dir,err:=os.Lstat(filepath.Dir(path))
 if err!=nil{return err}
 if !dir.IsDir()||dir.Mode().Perm()&0022!=0{
  return errors.New("payment socket directory must not be group/world writable")
 }
 if _,err=os.Lstat(path);err==nil{
  return errors.New("payment socket already exists; inspect before removal")
 }else if !os.IsNotExist(err){return err}
 public,err:=billing.LoadVerificationKey()
 if err!=nil{return err}
 if len(public)==0{return errors.New("ELX_PAYMENT_VERIFY_KEY must be configured")}
 listener,err:=net.Listen("unix",path)
 if err!=nil{return err}
 defer listener.Close()
 defer os.Remove(path)
 // A separate verifier UID can access the payment socket through a
 // dedicated group. The 0600 management socket must remain owned only by
 // Control, with a different UID. Never add the verifier to that UID/group.
 if raw:=strings.TrimSpace(os.Getenv("ELX_PAYMENT_GID"));raw!=""{
  gid,parseErr:=strconv.Atoi(raw)
  if parseErr!=nil||gid<1{return errors.New("invalid ELX_PAYMENT_GID")}
  if err=os.Chown(path,-1,gid);err!=nil{return err}
  if err=os.Chmod(path,0660);err!=nil{return err}
 }else{
  if err=os.Chmod(path,0600);err!=nil{return err}
 }
 server:=&http.Server{
  Handler:billing.PaymentIngressHandler(db,public),
  ReadHeaderTimeout:5*time.Second,IdleTimeout:30*time.Second,
 }
 done:=make(chan struct{})
 go func(){
  select{
  case <-ctx.Done():
   shutdown,cancel:=context.WithTimeout(context.Background(),5*time.Second)
   _=server.Shutdown(shutdown)
   cancel()
  case <-done:
  }
 }()
 err=server.Serve(listener)
 close(done)
 if errors.Is(err,http.ErrServerClosed)&&ctx.Err()!=nil{return nil}
 return err
}
