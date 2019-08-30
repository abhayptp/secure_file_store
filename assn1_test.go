package assn1

import "github.com/sarkarbidya/CS628-assn1/userlib"
import "testing"

import "reflect"

// You can actually import other stuff if you want IN YOUR TEST
// HARNESS ONLY.  Note that this is NOT considered part of your
// solution, but is how you make sure your solution is correct.

func TestInitUser(t *testing.T) {
	t.Log("Initialization test")
	userlib.DebugPrint = true
	_, err1 := InitUser("abhays", "adfsadf")
	if err1 == nil {
		t.Log("Initialized user")

	} else {
		t.Error("Failed to initialize valid user", err1)
	}

	// add more test cases here
}

func TestUserStorage(t *testing.T) {
	u1, err1 := GetUser("abhays", "adfsadf")
	if err1 == nil {
		t.Log("Loaded data for valid user", u1)
	} else {
		t.Error("Cannot load data for invalid user", err1)
	}

	// add more test cases here
}

func TestFileStoreLoadAppend(t *testing.T) {
	u1, err1 := GetUser("abhays", "adfsadf")
	if err1 != nil {
		t.Error(err1)
	}
	n := 800
	data1 := userlib.RandomBytes(4096 * n)
	err := u1.StoreFile("file1", data1)
	if err != nil {
		t.Error(err)
	}

	data2, err1 := u1.LoadFile("file1", (n - 1))
	if err1 != nil {
		t.Error(err1)
	}

	if !reflect.DeepEqual(data1[4096*(n-1):], data2) {
		t.Error("data corrupted")
	} else {
		t.Log("data is not corrupted")
	}
	//err = u1.AppendFile("file1", data1)
	//if err != nil {
	//t.Error(err)
	//}
	//data2, err1 = u1.LoadFile("file1", 0)
	//if !reflect.DeepEqual(data1, data2) {
	//t.Error("data corrupted")
	//} else {
	//t.Log("data is not corrupted")
	//}

	// add test cases here
}

func TestFileShareReceive(t *testing.T) {
	// add test cases here
}
