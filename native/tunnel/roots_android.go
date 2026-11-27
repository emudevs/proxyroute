package tunnel

import "os"

func init() {
	// Android 14 and newer deliver current system roots through Conscrypt.
	os.Setenv("SSL_CERT_DIR", "/apex/com.android.conscrypt/cacerts:/system/etc/security/cacerts")
}
