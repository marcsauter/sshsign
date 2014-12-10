# sshsign

## Description
package `sshsign` creates and verifies signatures using an ssh key pair. Usually the private key is already PEM encoded. To convert the public key use:

    ssh-keygen -e -m PKCS8 -f id_dsa.pub > id_dsa.pub.pkcs8

## Usage
### With an unencrypted private key

    package main
    
    import (
        "bytes"
        "log"
        "os"
    
        "sshsign"
    )
    
    func main() {
        testdata := []byte("Some test data!")
    
        f, err := os.Open("id_rsa_unencrypted")
        if err != nil {
            log.Fatal(err)
        }
    
        s, err := sshsign.NewSigner(f, nil)
        if err != nil {
            log.Fatal(err)
        }
    
        sig, err := s.Sign(testdata)
        if err != nil {
            log.Fatal(err)
        }
    
        f, err = os.Open("id_rsa_unencrypted.pub.pkcs8")
        if err != nil {
            log.Fatal(err)
        }
        v, err := sshsign.NewVerifier(f)
        if err != nil {
            log.Fatal(err)
        }
    
        if err := v.Verify(testdata, sig); err != nil {
            log.Fatal(err)
        }
    }

### With an encrypted private key

    package main
    
    import (
        "bytes"
        "log"
        "os"
    
        "sshsign"
    )
    
    func main() {
        testdata := []byte("Some test data!")
    
        f, err := os.Open("id_rsa")
        if err != nil {
            log.Fatal(err)
        }
    
        s, err := sshsign.NewSigner(f, bytes.NewBufferString("123ewq"))
        if err != nil {
            log.Fatal(err)
        }
    
        sig, err := s.Sign(testdata)
        if err != nil {
            log.Fatal(err)
        }
    
        f, err = os.Open("id_rsa.pub.pkcs8")
        if err != nil {
            log.Fatal(err)
        }
        v, err := sshsign.NewVerifier(f)
        if err != nil {
            log.Fatal(err)
        }
    
        if err := v.Verify(testdata, sig); err != nil {
            log.Fatal(err)
        }
    }

## Author
* [Marc Sauter](mailto:marc.sauter@bluewin.ch)


