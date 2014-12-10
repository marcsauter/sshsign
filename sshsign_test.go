package sshsign

import (
	"bytes"
	"testing"
)

var id_rsa_unencrypted *bytes.Buffer = bytes.NewBufferString(`
-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEApZVa0DkJtSt5tPdkOYjQ++1kElgbe4zJpomnI0jt0AG/hEJT
ImWccVC33xjY7LStkmHyw8cj2Tvv5fcLPy0oxFGv8fwN/adFZ/l9BeNqaqRXZEoJ
NDpCmFCvImtdbfAkmQO7TPusL50rmpt33KdetycOYKfwvbN6p+hulRtEuzUZWtot
L5tN/adJAYp84E7AUh+GYh2IqCZncP/KhnlqeoweCGaH+8DggXr94z30uknblk3H
hSCP9aDxroAOtpsBdLJriqJTerreivjsG5XMv+N5VXJIKymSeIUdLUwX1GGHYuGU
S+GM1dNWbcAyTByi/vA3rYQQS6dEg3PW5uF/VwIDAQABAoIBAGP4mKu+xC2t4f1w
oAJcqFByM0kgCPe/OMBju5WCIpLDe23O3YKW9q0zntADoHTJYUJQANJTGUG+/khJ
r3ClQ0fESgY/t/K9Wxo7d1BmzYk1T84tJQFza2Gq1RJi4DXQF0iLCDqieIMG0Zy2
4NdH9dd+rR+ORbtC8XsOyjUcEZM0sy6xcG+AIJ2SYFYrlUIHE27GDI4Dg8P/Tevv
yP/tK/dKB0JL+fn11licWPiUvFsErtkHNWeOBPwPmZ4Z5snItZLjF6I+O8jy6rju
V1JU7qRPh/goQEv69FNsK+IVPxuK5skl8xIaso6knMqVMPCIzZ9rJ19312cBW6aO
q0tHfIECgYEA1GPqqO4rEULEqGg01bQsUVq2/EO20B05Ni+7Yf8LWfLPSdgj1PSt
/zcYGgk3DBsRPwgsmpnEwdKRZdqpxrdlUCB9Dpr/l9+NJhef/qqp+tKKkBA5mEGv
qJ2nVZqs0lcIem2XekNNp6LFeAIN87hLHTlNh34MBJfc6xhDF+OlPLsCgYEAx5UU
yerKTBDJLOoAYj6wHUC9w9sCtgJ4TuRSqW/JtF7PKTNYW9O640R35NretjXVRiHq
ArEoyxHY2hoaXUw6+extZtbbXrQ9BHWrbgGPX0Xd9LYN+6jpZoBI7Nm7US6cAv6G
ECWuQyIiZRpRe+0x6OOZU+HV5F94WIoTVcYkTBUCgYEAlBLxGEOsHQWay/qS02cg
+rsvFiMzglbNe1y93G2PAXAKWuZo3OCVqnhDwmsoSLVaScKuLj8EcUkX+5X+hb94
z+tGpPclOUIvSx5veoKLrYY5+oSFUwSAriLz9fe3g5IQJCLh1+iybCxMVgXAqmmT
XNWFmvAi+tTRvcoVhMM+gV8CgYADkOtdLD/PGiGuFsRI/RvCegyp+jjTLboelr/P
XTr6aRNEhjFW+rKFKw0FXs/J665S4Xo/8BBtiHUaeIruDdWj75CI3N/wkkHg2YVl
osuABUyQ+cvIKl15QmOLL9zD95Q8DXYxxaqWcn6w1caM81EH+0EbGZbrzLTmyBjO
WIr/fQKBgQDLoaUxbiBI2b3CWpvZkErp1FrCwc3sXYaknwiQNrZbCeRA7Od6cYQh
8tPU9ZE0Cd0nkeJcaqdgZDXatcyNP0kihbhKUXq62Hgrg3s2umwz+8je91qDKNqY
0l6fj2uTb0z75KTWRWeD5sXQw1EgeW/SUxfUXCHX+msWVuCpbR7UQw==
-----END RSA PRIVATE KEY-----`)

var id_rsa_unencrypted_pub_pkcs8 *bytes.Buffer = bytes.NewBufferString(`
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEApZVa0DkJtSt5tPdkOYjQ
++1kElgbe4zJpomnI0jt0AG/hEJTImWccVC33xjY7LStkmHyw8cj2Tvv5fcLPy0o
xFGv8fwN/adFZ/l9BeNqaqRXZEoJNDpCmFCvImtdbfAkmQO7TPusL50rmpt33Kde
tycOYKfwvbN6p+hulRtEuzUZWtotL5tN/adJAYp84E7AUh+GYh2IqCZncP/Khnlq
eoweCGaH+8DggXr94z30uknblk3HhSCP9aDxroAOtpsBdLJriqJTerreivjsG5XM
v+N5VXJIKymSeIUdLUwX1GGHYuGUS+GM1dNWbcAyTByi/vA3rYQQS6dEg3PW5uF/
VwIDAQAB
-----END PUBLIC KEY-----`)

var id_rsa *bytes.Buffer = bytes.NewBufferString(`
-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-128-CBC,3658819C6BFABACFB01BB013440F6F1A

IW2TpGwuGxUpGGBBui4/pWAVYnyrm1DE/rRihKIBuKF0b7pwBpCQpiSyJMOTMVG3
IQ3W7zDo7lmLvmx/UkbCG4RPse7hF1ebF5FO5qY8uON5f8L7IqbseSicBwXmDVgm
zOHzB2sw0I1nQLKqveo+HhVo9y8ln39YevJ0ufpvqjqCoTJGp9GWX6oGg50It+pr
Vb03i2BW67Uo/0bBXZDbvUnOmL5sn79w0X+frnaooLwSWwzbPCYIqayVEFYwdgCL
Hbxw8nlUkohliIh8r7dFHd4k3iCL6G0HD5uu7QqLHbA/HI45I+xp1RTR09YrrDPa
pBBEwQ9UVsR6fUJ+xzXCsSBWjuOG/qiXzuY+sXbHoIwZCC+OunCaWjFtMlKRQdRe
z5Es/y1qM2JwCL+UzDxFoEsTARmfxen+csplqY9KFkuybapbEDTuiDk/oCTGTo03
NlR8j8pgaTqdeaQpC9cOm900tPuq30Gd3Mwow2C+3N66QWebQ7GJ6EsHknITyf34
9r9v6z1BeFmaIJW7pSm/NdkL/3kAbGkFKvryNveudL0MC/c527JqhZKL4S+Oblfb
Xz0cfqIHm4bJVdNWvOLmjBh9xOcPzWpsUxznCeZVtUvNGMsFlj0pO7YwlImlCDcl
zv/SZ7H0unt5tQX9mtZeoOtC5hAdYhayXi0v8zjwQ67USC1aYOA8mlSRMVmyHF9W
mbBxxZEWDKUBrHoulcYh7XK/sicE6hoJXAiw/k04zadc5xOsKNxino72ONr2bEHa
BgG89+xKa1oOJwmZWKw3eFXkQ2DC2QzJQo/GFnB8Xg9dRhIbIB0Vx/hANb4zjHfx
f7SFJ0oE4YWrWJ5mnRgiLAnsFGP/4Tmw4cPdTkeWJSpRoAP//wj1MKq0hTbobaWS
X21W5ipiSKVMp9tLxUr8q9et7HczCD0WZF83ujdXuNVYQq+HIsg4pvCYTPthATPr
MkyCfHoYYpYocrhm9gxob2CkZo2Lxv8vpiPHfEAxhl+yRWhdDbbnPrvs1rtI4yrQ
vXhDm5JsNiKCunQGdEM0VNhoHwteFLffiVnX3Cj2elFjdD+E+s05Ye1HCvGQMBQI
Cgp76wel7La23armtLp7F1zZMsY+1b6iWVFsaCVEFBrKI7tWcKcHtIptUCQVvWRw
ZdNtTJmpKedkwYn3Xu6rsHVXLR+1MEWVAFG4xFYGbsynhb8Pon+viWOS1EaNPXEi
MhMSI2rFIJfLkJnPFkP96xYVnmA9gKVp/9jPEbp4bb6L6KV6NaUynSHZWisX+qKh
MRxuwooNcbuz2sljjHHB1RmwwVlb2dPl3RRVHMSFXJj+0YA5nF+MdTWVeEVNTw0V
1pniaJqsFv0rdMYst8Pub90WT4k5sD3mM2KUSiHOjw/IPe8uTLNVQeWpEzFxxIZC
QcER1+q4fBKK0aUItJupPdwb8N74EvSO0sO+cmdpGkwO6gZv/QLuEiJuc8QEVJ+q
C1CgmbfTf6Kv9Tvv+6gbZ3yBNbMd1yEKJoWeLb97usw+NZZAD+2T/pEOQui3N3dd
0mD2vitr8NIDvs50P1HTkiMzyCTM3SB+MvHPEG3H/L0SStJ4d0iDFRybWx7jIMAH
-----END RSA PRIVATE KEY-----`)

var id_rsa_pub_pkcs8 *bytes.Buffer = bytes.NewBufferString(`
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAznSQAHYF9xPvr8O68r7U
o9o17qQfBaMahQFMcGBWclBuHivGA5NvTBDSP9nr8Czv05FZN21uwL8fON82HLPh
HUp0IXOZgZgM64rPohO40Th0daDf7qwLwPkXmHmxs2fDgwV7NKF18MXQjJBpEto6
mNvYWYmhES9hIzsM61EY7PoT8wl+YFbrpZwQLevE1EMhUNUGAX+w/UL0uACCK77d
6FUixK//lcVujSF9TUaKRykKe9E7Qefd/i3exqaNYO+tvnTbFjvT2Y7hbWZiXvCJ
m+DaxJmCQVlvp4dIRY48pYYxJhAHZQnUYLzsDNbFzxVBW0n9L/YveqH6SBch7zFV
WQIDAQAB
-----END PUBLIC KEY-----`)

func TestSignVrfy(t *testing.T) {
	testdata := []byte("This is test string!")

	s, err := NewSigner(id_rsa_unencrypted, nil)
	if err != nil {
		t.Fatal(err)
	}

	sig, err := s.Sign(testdata)
	if err != nil {
		t.Fatal(err)
	}

	v, err := NewVerifier(id_rsa_unencrypted_pub_pkcs8)
	if err != nil {
		t.Fatal(err)
	}

	if err := v.Verify(testdata, sig); err != nil {
		t.Fatal(err)
	}
}

func TestSignVrfyEncrypted(t *testing.T) {
	testdata := []byte("This is test string!")

	s, err := NewSigner(id_rsa, bytes.NewBufferString("123ewq"))
	if err != nil {
		t.Fatal(err)
	}

	sig, err := s.Sign(testdata)
	if err != nil {
		t.Fatal(err)
	}

	v, err := NewVerifier(id_rsa_pub_pkcs8)
	if err != nil {
		t.Fatal(err)
	}

	if err := v.Verify(testdata, sig); err != nil {
		t.Fatal(err)
	}
}
