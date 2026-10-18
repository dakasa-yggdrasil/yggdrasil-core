//go:build linux && nativequalification
package main
import "testing"
func TestPostlossExpiryPreservesEveryOtherOriginalField(t *testing.T){
 before:=[]byte(`{"grant":{"grant_id":"same","state":"issued"},"executor_id":"same","binding":{"protected":true},"settlement_token_sha256":""}`)
 if !postlossOnlyExpiredStateChange(before,[]byte(`{"grant":{"state":"expired","grant_id":"same"},"executor_id":"same","binding":{"protected":true},"settlement_token_sha256":""}`)){t.Fatal("equivalent original row expiry refused")}
 for _,after:=range []string{`{"grant":{"grant_id":"same","state":"expired"},"executor_id":"foreign","binding":{"protected":true},"settlement_token_sha256":""}`,`{"grant":{"grant_id":"same","state":"expired"},"executor_id":"same","binding":{"protected":0},"settlement_token_sha256":""}`,`{"grant":{"grant_id":"same","state":"expired"},"executor_id":"same","binding":{"protected":true},"settlement_token_sha256":"actual-token"}`} {if postlossOnlyExpiredStateChange(before,[]byte(after)){t.Fatal("expiry hid a foreign owner, type alias or actual redeemed token")}}
}
