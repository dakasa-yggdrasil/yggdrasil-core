//go:build linux && nativequalification

package capacitynativeqemu

import (
 "context"
 "io"
 "os"
 "path/filepath"
 "time"
 "golang.org/x/sys/unix"
)

// The Source fault really closes the original creator reply with zero bytes.
// This reader owns the actual opened FD, EOF and Close, retaining those facts.
// Only a later independent native reader may discover the created lifetime.
func readSourceLostCreateReply(ctx context.Context,dir string) error {
 path:=filepath.Join(dir,"creator-original.json")
 for {
  if ctx.Err()!=nil{return ErrOriginalUnknown}
  fd,err:=unix.Open(path,unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC,0)
  if err==unix.ENOENT { select{case<-ctx.Done():return ErrOriginalUnknown;case<-time.After(20*time.Millisecond):};continue }
  if err!=nil{return ErrOriginalUnknown}
  file:=os.NewFile(uintptr(fd),path);var before,after unix.Stat_t
  start:=time.Now().UTC();err=unix.Fstat(fd,&before)
  raw,readErr:=io.ReadAll(io.LimitReader(file,65537));readAt:=time.Now().UTC();postErr:=unix.Fstat(fd,&after);closeErr:=file.Close();closeAt:=time.Now().UTC()
  if err!=nil || readErr!=nil || postErr!=nil || closeErr!=nil || len(raw)!=0 || before.Mode&unix.S_IFMT!=unix.S_IFREG || before.Size!=0 || before.Dev!=after.Dev || before.Ino!=after.Ino || before.Size!=after.Size || ctx.Err()!=nil{return ErrOriginalUnknown}
  fact:=struct{Schema string `json:"schema"`;Class string `json:"class"`;BodyBytes int `json:"body_bytes"`;BodySHA256 string `json:"body_sha256"`;ReadStartedAt time.Time `json:"read_started_at"`;EOFReturnedAt time.Time `json:"eof_returned_at"`;CloseReturnedAt time.Time `json:"close_returned_at"`;Complete bool `json:"complete"`}{"original_source_create_reply_v1","owning_reply_empty_eof_uncertain",0,digest(raw),start,readAt,closeAt,false}
  _,err=Publish(ctx,filepath.Join(dir,"core-original-create-transport-uncertain.json"),fact);return err
 }
}
