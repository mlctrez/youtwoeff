// FIDO U2F Go Library
// Copyright 2015 The FIDO U2F Go Library Authors. All rights reserved.
// Use of this source code is governed by the MIT
// license that can be found in the LICENSE file.

package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/boltdb/bolt"
	"github.com/mlctrez/youtwoeff/utfcontent"
	"github.com/tstranex/u2f"
	"log"
	"math/big"
	"net/http"
	"os"
	"reflect"
	"time"
)

type YouTwoEff struct {
	appID string
	db    *bolt.DB
}

func (ytf *YouTwoEff) trustedFacets() []string {
	return []string{ytf.appID}
}

func toJson(i interface{}) string {
	bo, err := json.MarshalIndent(i, "", "  ")
	if err != nil {
		return err.Error()
	}
	_ = bo
	return reflect.TypeOf(i).String()

	//return string(bo)
}

type RegistrationSer struct {
	// Raw serialized registration data as received from the token.
	Raw []byte

	KeyHandle []byte
	// important parts of ecsda.PublicKey
	X, Y *big.Int

	// AttestationCert can be nil for Authenticate requests.
	// TODO: make this part serialzable as well
	AttestationCert *x509.Certificate
}

func (ytf *YouTwoEff) getRegistrations(user string) (regs []u2f.Registration, err error) {
	regs = make([]u2f.Registration, 0)
	err = ytf.db.View(func(tx *bolt.Tx) error {
		userBucket := tx.Bucket([]byte(user))
		if userBucket == nil {
			// no registrations yet for this user
			return nil
		}
		// registrations and counters are stored in pairs, each with a suffix of -N
		for i := 0; i < 10; i++ {
			aReg := userBucket.Get([]byte(fmt.Sprintf("reg-%d", i)))
			if aReg == nil {
				continue
			}
			rs := RegistrationSer{}
			err = json.Unmarshal(aReg, &rs)
			if err != nil {
				// TODO: just log invalid registrations?
				return err
			}

			rr := u2f.Registration{
				Raw:       rs.Raw,
				KeyHandle: rs.KeyHandle,
				PubKey: ecdsa.PublicKey{
					Curve: elliptic.P256(),
					X:     rs.X,
					Y:     rs.Y,
				},
				AttestationCert: rs.AttestationCert,
			}

			regs = append(regs, rr)
		}
		return nil
	})
	for _, r := range regs {
		fmt.Printf("found reg %q\n", base64.StdEncoding.EncodeToString(r.KeyHandle))
	}
	return regs, err
}

func (ytf *YouTwoEff) registerRequest(w http.ResponseWriter, r *http.Request) {
	user := r.FormValue("user")
	if user == "" {
		http.Error(w, "no user error", http.StatusBadRequest)
		return
	}
	c, err := u2f.NewChallenge(ytf.appID, ytf.trustedFacets())
	if err != nil {
		log.Printf("u2f.NewChallenge error: %v", err)
		http.Error(w, "error", http.StatusInternalServerError)
		return
	}
	ytf.setChallenge(user, c)
	if err != nil {
		http.Error(w, "error", http.StatusInternalServerError)
		return
	}

	// retrieve previous registration data for user
	regs, err := ytf.getRegistrations(user)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	req := u2f.NewWebRegisterRequest(c, regs)

	//log.Printf("Register Challenge: %s", toJson(req))
	json.NewEncoder(w).Encode(req)
}

func (ytf *YouTwoEff) getChallenge(user string) (challenge *u2f.Challenge, err error) {
	if user == "" {
		return nil, errors.New("empty user")
	}
	err = ytf.db.Update(func(tx *bolt.Tx) error {
		userBucket, e := tx.CreateBucketIfNotExists([]byte(user))
		if e != nil {
			return e
		}
		cb := userBucket.Get([]byte("challenge"))
		if cb == nil {
			return errors.New("challenge for user missing")
		}

		e = userBucket.Delete([]byte("challenge"))
		if e != nil {
			return e
		}

		challenge = &u2f.Challenge{}
		return json.Unmarshal(cb, challenge)
	})
	return challenge, err
}

func (ytf *YouTwoEff) saveRegistration(user string, reg *u2f.Registration) error {
	if user == "" {
		return errors.New("empty user")
	}
	err := ytf.db.Update(func(tx *bolt.Tx) error {
		userBucket, e := tx.CreateBucketIfNotExists([]byte(user))
		if e != nil {
			return e
		}
		saved := false
		for i := 0; i < 10; i++ {
			regSlot := fmt.Sprintf("reg-%d", i)
			aReg := userBucket.Get([]byte(regSlot))
			if aReg != nil {
				continue
			}
			fmt.Println("saving in slot " + regSlot)

			rs := &RegistrationSer{
				AttestationCert: reg.AttestationCert,
				X:               reg.PubKey.X,
				Y:               reg.PubKey.Y,
				KeyHandle:       reg.KeyHandle,
				Raw:             reg.Raw,
			}

			rb, e := json.Marshal(rs)
			if e != nil {
				return e
			}
			e = userBucket.Put([]byte(regSlot), rb)
			if e == nil {
				saved = true
			}
			return e
		}
		if !saved {
			return errors.New("number of slots exceeded")
		}
		return nil
	})
	return err
}

func (ytf *YouTwoEff) registerResponse(w http.ResponseWriter, r *http.Request) {

	var regResp u2f.RegisterResponse
	if err := json.NewDecoder(r.Body).Decode(&regResp); err != nil {
		http.Error(w, "invalid response: "+err.Error(), http.StatusBadRequest)
		return
	}
	user := r.FormValue("user")
	if user == "" {
		http.Error(w, "no user error", http.StatusBadRequest)
		return
	}

	challenge, err := ytf.getChallenge(user)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	reg, err := u2f.Register(regResp, *challenge, nil)
	if err != nil {
		log.Printf("u2f.Register error: %v", err)
		http.Error(w, "error verifying response", http.StatusInternalServerError)
		return
	}

	// save registrations for user
	err = ytf.saveRegistration(user, reg)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	//log.Printf("Register Registration KeyHandle: %X\n", reg.KeyHandle)

	//log.Printf("Register Registration: %s", toJson(reg))
	w.Write([]byte("success"))
}

func (ytf *YouTwoEff) signRequest(w http.ResponseWriter, r *http.Request) {

	user := r.FormValue("user")
	if user == "" {
		http.Error(w, "no user", http.StatusBadRequest)
		return
	}

	regs, err := ytf.getRegistrations(user)

	if len(regs) == 0 {
		http.Error(w, "no registrations for this user", http.StatusBadRequest)
		return
	}

	c, err := u2f.NewChallenge(ytf.appID, ytf.trustedFacets())
	if err != nil {
		log.Printf("u2f.NewChallenge error: %v", err)
		http.Error(w, "error", http.StatusInternalServerError)
		return
	}
	err = ytf.setChallenge(user, c)
	if err != nil {
		http.Error(w, "save challenge error", http.StatusInternalServerError)
		return
	}

	req := c.SignRequest(regs)

	//log.Printf("Sign WebSignRequest : %s", toJson(req))
	json.NewEncoder(w).Encode(req)
}

func (ytf *YouTwoEff) setChallenge(user string, challenge *u2f.Challenge) error {
	err := ytf.db.Update(func(tx *bolt.Tx) error {
		userBucket, e := tx.CreateBucketIfNotExists([]byte(user))
		if e != nil {
			return e
		}
		cb, e := json.Marshal(challenge)
		if e != nil {
			return e
		}
		return userBucket.Put([]byte("challenge"), cb)
	})
	return err
}

func (ytf *YouTwoEff) signResponse(w http.ResponseWriter, r *http.Request) {

	var signResp u2f.SignResponse
	if err := json.NewDecoder(r.Body).Decode(&signResp); err != nil {
		http.Error(w, "invalid response: "+err.Error(), http.StatusBadRequest)
		return
	}

	user := r.FormValue("user")
	if user == "" {
		http.Error(w, "error", http.StatusBadRequest)
		return
	}

	//log.Printf("Sign SignResponse: %s", toJson(&signResp))

	challenge, err := ytf.getChallenge(user)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	regs, err := ytf.getRegistrations(user)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if len(regs) == 0 {
		http.Error(w, "registration missing", http.StatusBadRequest)
		return
	}

	//var err error
	for _, reg := range regs {
		// TODO: retrieve counter

		prevCount, err := ytf.retrieveCounter(user, signResp.KeyHandle)
		if err != nil {
			http.Error(w, "counter error", http.StatusInternalServerError)
			return
		}

		newCounter, authErr := reg.Authenticate(signResp, *challenge, prevCount)
		if authErr == nil {
			log.Printf("newCounter: %d", newCounter)
			// TODO: save counter
			err = ytf.saveCounter(user, signResp.KeyHandle, newCounter)
			if err != nil {
				http.Error(w, "counter error", http.StatusInternalServerError)
				return
			}
			w.Write([]byte("success"))
			return
		}
	}

	log.Printf("VerifySignResponse error: %v", err)
	http.Error(w, "error verifying response", http.StatusInternalServerError)
}
func (ytf *YouTwoEff) retrieveCounter(user string, keyHandle string) (prevCounter uint32, err error) {
	if user == "" {
		return 0, errors.New("empty user")
	}
	err = ytf.db.Update(func(tx *bolt.Tx) error {
		userBucket, e := tx.CreateBucketIfNotExists([]byte(user))
		if e != nil {
			return e
		}
		cb := userBucket.Get([]byte(keyHandle))
		if cb == nil {
			return nil
		}
		pcl, err := binary.ReadUvarint(bytes.NewReader(cb))
		if err != nil {
			return err
		}
		prevCounter = uint32(pcl)
		fmt.Println("read previous counter for ", keyHandle, "as", prevCounter)
		return nil
	})
	return prevCounter, err
}
func (ytf *YouTwoEff) saveCounter(user string, keyHandle string, counter uint32) (err error) {
	if user == "" {
		return errors.New("empty user")
	}
	err = ytf.db.Update(func(tx *bolt.Tx) error {
		userBucket, e := tx.CreateBucketIfNotExists([]byte(user))
		if e != nil {
			return e
		}
		bb := make([]byte, 32)
		bw := binary.PutUvarint(bb, uint64(counter))

		return userBucket.Put([]byte(keyHandle), bb[:bw])
	})
	return err
}

func indexHandler(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte(utfcontent.IndexHTML))
}

func u2fApiJsHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/javascript")
	w.Write([]byte(utfcontent.U2fApiJs))
}

func main() {

	//os.Remove("store.db")
	log.SetOutput(os.Stdout)

	db, err := bolt.Open("store.db", 0600, &bolt.Options{Timeout: 1 * time.Second})
	if err != nil {
		panic(err)
	}

	host := "local.crawford.localnet"

	ytf := &YouTwoEff{
		appID: "https://" + host + ":8443",
		db:    db,
	}

	http.HandleFunc("/", indexHandler)
	http.HandleFunc("/u2f-api.js", u2fApiJsHandler)
	http.HandleFunc("/registerRequest", ytf.registerRequest)
	http.HandleFunc("/registerResponse", ytf.registerResponse)
	http.HandleFunc("/signRequest", ytf.signRequest)
	http.HandleFunc("/signResponse", ytf.signResponse)

	log.Printf("Running on %s", ytf.appID)

	s := &http.Server{Addr: "127.0.0.1:8443"}

	certFile := fmt.Sprintf("/etc/ssl/private/%s.crt", host)
	keyFile := fmt.Sprintf("/etc/ssl/private/%s.key", host)
	log.Fatal(s.ListenAndServeTLS(certFile, keyFile))
}
