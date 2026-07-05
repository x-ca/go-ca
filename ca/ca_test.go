/*
Copyright © 2022 xiexianbin.cn
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at
    http://www.apache.org/licenses/LICENSE-2.0
Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package ca

import (
	"math"
	"math/big"
	"testing"
)

func TestNewRootCAEC(t *testing.T) {
	root, err := NewRootCA("ec", 0, "P256")
	if err != nil {
		t.Fatalf("NewRootCA: %v", err)
	}
	if !root.Cert.IsCA {
		t.Error("root cert should be CA")
	}
	if root.Cert.MaxPathLen != 1 {
		t.Errorf("MaxPathLen = %d, want 1", root.Cert.MaxPathLen)
	}
	if root.Cert.SubjectKeyId == nil {
		t.Error("root cert should have SubjectKeyId")
	}
}

func TestNewRootCAUnsupportedKeyType(t *testing.T) {
	if _, err := NewRootCA("dsa", 0, ""); err == nil {
		t.Fatal("expected error for unsupported key type, got nil")
	}
}

func TestNewRootCAUnsupportedCurve(t *testing.T) {
	if _, err := NewRootCA("ec", 0, "P999"); err == nil {
		t.Fatal("expected error for unsupported curve, got nil")
	}
}

func TestRandSerialFixedAndRandom(t *testing.T) {
	t.Run("fixed positive", func(t *testing.T) {
		s, err := randSerial(5)
		if err != nil || s.Cmp(big.NewInt(5)) != 0 {
			t.Errorf("randSerial(5) = %v err %v, want 5", s, err)
		}
	})
	t.Run("random within range", func(t *testing.T) {
		s, err := randSerial(0)
		if err != nil {
			t.Fatalf("randSerial(0): %v", err)
		}
		if s.Sign() < 0 || s.Cmp(big.NewInt(math.MaxInt64)) >= 0 {
			t.Errorf("randSerial(0) = %v, want in [0, MaxInt64)", s)
		}
	})
}
