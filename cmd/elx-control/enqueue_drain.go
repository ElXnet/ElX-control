package main

import (
	"context"
	"database/sql"
	"errors"
	"flag"
	"fmt"
	"os"

	"github.com/google/uuid"
	"github.com/ElXnet/ElX-control/internal/elxcontrol/session"
)

// enqueueDrain is a privileged Control-side operation to be invoked ONLY
// after the personal-cabinet API authorizes the subscription owner. It does
// not accept bearer subscription URLs and does not release an occupied slot.
func enqueueDrain(ctx context.Context,db *sql.DB,args []string) error {
	fs:=flag.NewFlagSet("enqueue-drain",flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	owner:=fs.String("owner","","session owner UUID")
	if err:=fs.Parse(args);err!=nil {return err}
	id,err:=uuid.Parse(*owner)
	if fs.NArg()!=0 || err!=nil || id==uuid.Nil || id.String()!=*owner {
		return errors.New("enqueue-drain requires an existing canonical owner UUID")
	}
	if err:=session.QueueDrain(ctx,db,id);err!=nil {return err}
	fmt.Println("queued",id)
	return nil
}
