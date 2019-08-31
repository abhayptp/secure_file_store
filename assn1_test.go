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
		t.Error("Failed to initialize user", err1)
	}
	_, err1 = InitUser("abhays", "adfsadf")
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

func TestFileStoreLoadAppend1(t *testing.T) {
	u1, err1 := GetUser("abhays", "adfsadf")
	if err1 != nil {
		t.Error(err1)
	}
	n := 1
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

func TestFileStoreLoadAppend(t *testing.T) {
	u1, err1 := GetUser("abhays", "adfsadf")
	if err1 != nil {
		t.Error(err1)
	}
	n := 700
	data1 := userlib.RandomBytes(4096 * n)
	err := u1.StoreFile("file2", data1)
	if err != nil {
		t.Error(err)
	}
	data2 := userlib.RandomBytes(4096)
	err1 = u1.AppendFile("file2", data2)
	if err1 != nil {
		t.Error(err1)
	}
	data3, err2 := u1.LoadFile("file2", n)
	if err2 != nil {
		t.Error(err2)
	}

	if !reflect.DeepEqual(data3, data2) {
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
	u1, _ := GetUser("abhays", "adfsadf")
	u2, _ := InitUser("nishankm", "dfadsf")
	msgId, err := u1.ShareFile("file1", u2.Username)
	if err != nil {
		t.Error(err)
	}
	err = u2.ReceiveFile("file2", u1.Username, msgId)
	if err != nil {
		t.Error(err)
	}

	data1, err1 := u1.LoadFile("file1", 0)
	if err1 != nil {
		t.Error(err1)
	}
	data2, err2 := u2.LoadFile("file2", 0)
	if err2 != nil {
		t.Error(err2)
	}
	if !reflect.DeepEqual(data1, data2) {
		t.Error("data is corrupted")
	} else {
		t.Log("data is not corrupted")
	}

	// add test cases here
}

func TestFileRevoke(t *testing.T) {
	u1, _ := GetUser("abhays", "adfsadf")
	u2, _ := GetUser("nishankm", "dfadsf")
	err := u1.RevokeFile("file9")
	if err != nil {
		t.Error(err)
	}
	b, err1 := u2.LoadFile("file2", 0)
	if err1 == nil {
		t.Log(b)
	} else {
		t.Error(err1)
	}

}
