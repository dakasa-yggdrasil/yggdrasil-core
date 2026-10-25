package capacity
import("encoding/json";"os";"testing";"time";"github.com/dakasa-yggdrasil/yggdrasil-core/model")
func TestGuestInstallationCrossSource(t *testing.T){
 path:=os.Getenv("INSTALLATION_CROSS_FIXTURE");if path==""{t.Skip("cross-source input not requested")}
 raw,err:=os.ReadFile(path);if err!=nil{t.Fatal(err)}
 var f struct{PublicKey string `json:"public_key"`;Receipt model.CapacityGuestOriginalProvisioningReceipt `json:"receipt"`;Confirmation model.CapacityGuestOriginalInstallationConfirmation `json:"confirmation"`;Deadline time.Time `json:"deadline"`;Now time.Time `json:"now"`}
 if err=json.Unmarshal(raw,&f);err!=nil{t.Fatal(err)}
 pre:=model.CapacityGuestOriginalProvisioningPreregistration{PreregistrationID:f.Receipt.PreregistrationID,OriginalDeadline:f.Deadline}
 if err=GuestOriginalInstallation(pre,f.Receipt,f.Confirmation,f.PublicKey,f.Now);err!=nil{t.Fatal("actual Guest signature rejected",err)}
 for _,name:=range []string{"early","late","foreign","old_message","digest","tampered_signature"}{t.Run(name,func(t *testing.T){c:=f.Confirmation;now:=f.Now;switch name{case "early":c.InstalledAt=f.Receipt.RecordedAt.Add(-time.Nanosecond);case "late":now=f.Deadline;case "foreign":c.PreregistrationID="10000000-0000-0000-0000-000000000002";case "old_message":c.Schema="guest_original_registration_v1";case "digest":c.EnrollmentSHA256=c.OriginalReceiptSHA256;case "tampered_signature":c.Signature="invalid"};if GuestOriginalInstallation(pre,f.Receipt,c,f.PublicKey,now)==nil{t.Fatal("unsafe cross-source confirmation accepted")}})}
}
