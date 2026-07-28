package model

// ClearSecretValue is an update-only marker used when an operator explicitly
// removes an optional secret. It is consumed before validation and storage.
const ClearSecretValue = "\x00TH_CLEAR_SECRET\x00"

// GenerateWireGuardCredentials prepares a key pair early enough for an
// interactive workflow to show the local public key before asking for peers.
func GenerateWireGuardCredentials(spec *WireGuardSpec) error {
	return ensureWireGuardKey(spec, true)
}

// GenerateIKECredentials prepares local IKE material before the remote
// credential prompt. PrepareNew still performs complete record validation.
func GenerateIKECredentials(spec *XFRMIKEv2Spec) error {
	return ensureIKECredentials(spec, true)
}
