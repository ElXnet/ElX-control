package main

import (
	"context"
	"database/sql"
	"errors"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/ElXnet/ElX-control/internal/elxcontrol/management"
	"github.com/ElXnet/ElX-control/internal/elxcontrol/lk"
)

// serveManagement intentionally has no TCP mode. Operators must protect the
// socket's parent directory as well as the resulting 0600 socket.
func serveManagement(ctx context.Context,db *sql.DB) error {
	path:=os.Getenv("ELX_MANAGEMENT_SOCKET")
	if path==""||!filepath.IsAbs(path)||path=="/" {
		return errors.New("ELX_MANAGEMENT_SOCKET must be an absolute Unix socket path")
	}
	parent,err:=os.Stat(filepath.Dir(path))
	if err!=nil{return err}
	if !parent.IsDir()||parent.Mode().Perm()&0022!=0{
		return errors.New("management socket directory must not be writable by group or others")
	}
	if _,err:=os.Lstat(path);err==nil{
		return errors.New("management socket path already exists; inspect owner before cleanup")
	}else if !os.IsNotExist(err){return err}
	ln,err:=net.Listen("unix",path)
	if err!=nil{return err}
	defer ln.Close()
	defer os.Remove(path)
	if err:=os.Chmod(path,0600);err!=nil{return err}
	router:=http.NewServeMux()
	router.Handle("/v1/",management.Handler(management.SQLStore{DB:db}))
	router.Handle("/lk/v1/",lk.Handler(lk.Store{DB:db}))
	server:=&http.Server{Handler:router,
		ReadHeaderTimeout:5*time.Second,IdleTimeout:30*time.Second}
	done:=make(chan struct{})
	go func(){
		select{
		case <-ctx.Done():
			shutdownCtx,cancel:=context.WithTimeout(context.Background(),5*time.Second)
			_ = server.Shutdown(shutdownCtx)
			cancel()
		case <-done:
		}
	}()
	err=server.Serve(ln)
	close(done)
	if errors.Is(err,http.ErrServerClosed)&&ctx.Err()!=nil{return nil}
	return err
}
