package assn1

// You MUST NOT change what you import.  If you add ANY additional
// imports it will break the autograder, and we will be Very Upset.
//
import (
	// You neet to add with
	// go get github.com/sarkarbidya/CS628-assn1/userlib

	"github.com/sarkarbidya/CS628-assn1/userlib"

	// Life is much easier with json:  You are
	// going to want to use this so you can easily
	// turn complex structures into strings etc...

	"encoding/json"

	// Likewise useful for debugging etc
	"encoding/hex"

	// UUIDs are generated right based on the crypto RNG
	// so lets make life easier and use those too...
	//
	// You need to add with "go get github.com/google/uuid"
	"github.com/google/uuid"

	// Useful for debug messages, or string manipulation for datastore keys
	"strings"

	// Want to import errors
	"errors"
)

// This serves two purposes: It shows you some useful primitives and
// it suppresses warnings for items not being imported
func someUsefulThings() {
	// Creates a random UUID
	f := uuid.New()
	userlib.DebugMsg("UUID as string:%v", f.String())

	// Example of writing over a byte of f
	f[0] = 10
	userlib.DebugMsg("UUID as string:%v", f.String())

	// takes a sequence of bytes and renders as hex
	h := hex.EncodeToString([]byte("fubar"))
	userlib.DebugMsg("The hex: %v", h)

	// Marshals data into a JSON representation
	// test
	// Will actually work with go structures as well
	d, _ := json.Marshal(f)
	userlib.DebugMsg("The json data: %v", string(d))
	var g uuid.UUID
	json.Unmarshal(d, &g)
	userlib.DebugMsg("Unmashaled data %v", g.String())

	// This creates an error type
	userlib.DebugMsg("Creation of error %v", errors.New(strings.ToTitle("This is an error")))

	// And a random RSA key.  In this case, ignoring the error
	// return value
	var key *userlib.PrivateKey
	key, _ = userlib.GenerateRSAKey()
	userlib.DebugMsg("Key is %v", key)
}

var configBlockSize = 4096 //Do not modify this variable

//setBlockSize - sets the global variable denoting blocksize to the passed parameter. This will be called only once in the beginning of the execution
func setBlockSize(blocksize int) {
	configBlockSize = blocksize
}

// Helper function: Takes the first 16 bytes and
// converts it into the UUID type
func bytesToUUID(data []byte) (ret uuid.UUID) {
	for x := range ret {
		ret[x] = data[x]
	}
	return
}

//User : User structure used to store the user information
type User struct {
	Username      string
	PasswordHash  []byte
	RSAPrivateKey *userlib.PrivateKey

	// You can add other fields here if you want...
	// Note for JSON to marshal/unmarshal, the fields need to
	// be public (start with a capital letter)
}

type fileInode struct {
	CurBlock        int
	DirectP         [10]string
	IndirectP       string
	DoubleIndirectP string
}

func verifyHMACSign(data []byte, HMACkey []byte) (check bool) {
	data1 := data[:len(data)-userlib.HashSize]
	hmacVal0 := data[len(data)-userlib.HashSize:]
	h := userlib.NewHMAC(HMACkey)
	h.Write([]byte(data1))
	hmacVal1 := h.Sum(nil)
	check = userlib.Equal(hmacVal0, hmacVal1)
	return
}

func appendHMACSign(data []byte, HMACkey []byte) (data1 []byte) {
	h := userlib.NewHMAC(HMACkey)
	h.Write([]byte(data))
	hmacSign := h.Sum(nil)
	data1 = append(data, hmacSign...)
	return
}

func decryptAESLoad(key string, HMACKey []byte, AESKey []byte) (data []byte, err error) {
	data, ok := userlib.DatastoreGet(key)
	if !ok || data == nil {
		err = errors.New("Nil")
		return
	}
	hmacSign := []byte(data[len(data)-userlib.HashSize:])
	data = []byte(data[0 : len(data)-userlib.HashSize])
	h := userlib.NewHMAC(HMACKey)
	h.Write(data)
	hmacSign0 := h.Sum(nil)
	if !userlib.Equal(hmacSign0, hmacSign) {
		err = errors.New("Data compromised")
		return
	}
	stream := userlib.CFBDecrypter(AESKey, data[:userlib.BlockSize])
	stream.XORKeyStream(data[userlib.BlockSize:], data[userlib.BlockSize:])
	data = (data[userlib.BlockSize:])
	return
}

func encryptAESStore(key string, HMACKey []byte, AESKey []byte, data []byte) {
	cipherText := make([]byte, userlib.BlockSize+len(data))

	copy(cipherText[:userlib.BlockSize], userlib.RandomBytes(userlib.BlockSize))

	stream := userlib.CFBEncrypter(AESKey, cipherText[:userlib.BlockSize])
	stream.XORKeyStream(cipherText[userlib.BlockSize:], data)
	h := userlib.NewHMAC(HMACKey)
	h.Write([]byte(cipherText))
	hmacSign := h.Sum(nil)
	userlib.DatastoreSet(key, (append(cipherText, hmacSign...)))
}

func (file *fileInode) Load(offset int, HMACKey []byte, AESKey []byte) (data []byte, err error) {
	blocks := offset / configBlockSize
	if blocks > file.CurBlock {
		err = errors.New("Access offset greater than size of file")
		return
	}
	if blocks < 10 {
		data, err = decryptAESLoad(file.DirectP[blocks], HMACKey, AESKey)
		return
	}
	blocks -= 10
	if blocks <= 256 {
		data, err = decryptAESLoad(file.IndirectP, HMACKey, AESKey)
		if err != nil {
			return
		}
		mblock := data[blocks*8 : blocks*8+8]
		data, err = decryptAESLoad(string(mblock), HMACKey, AESKey)
		return
	}
	blocks -= 256
	indblock := blocks / 256
	dirblock := blocks % 256
	data, err = decryptAESLoad(file.DoubleIndirectP, HMACKey, AESKey)
	if err != nil {
		return
	}
	indblockAdd, err := decryptAESLoad(string(data[indblock*8:indblock*8+8]), HMACKey, AESKey)
	if err != nil {
		return
	}
	data, err = decryptAESLoad(string(indblockAdd), HMACKey, AESKey)
	if err != nil {
		return
	}
	dirblockAdd, err := decryptAESLoad(string(data[dirblock*8:dirblock*8+8]), HMACKey, AESKey)
	if err != nil {
		return
	}
	data, err = decryptAESLoad(string(dirblockAdd), HMACKey, AESKey)
	return
}

func (file *fileInode) Append(data []byte, HMACKey []byte, AESKey []byte) error {
	if len(data)%configBlockSize != 0 {
		err := errors.New("File length not multiple of block size")
		return err
	}
	blockCount := len(data) / configBlockSize
	curBlock := 0
	//Go to current block
	//cbpos denote the block number which is yet not filled
	cbpos := file.CurBlock
	for cbpos < 10 {
		f := uuid.New()
		file.DirectP[cbpos] = string(f[:])
		encryptAESStore(file.DirectP[cbpos], HMACKey, AESKey, data[curBlock*configBlockSize:curBlock*(configBlockSize+1)])
		cbpos++
		curBlock++
	}
	if curBlock == blockCount {
		return nil
	}
	if cbpos == 10 {
		f := uuid.New()
		file.IndirectP = string(f[:])
		encryptAESStore(file.IndirectP, HMACKey, AESKey, make([]byte, 256*16))
	}
	cbpos -= 10
	if cbpos < 256 {
		directp, err := decryptAESLoad(file.IndirectP, HMACKey, AESKey)
		if err != nil {
			return err
		}
		for cbpos < 256 {
			f := uuid.New()
			copy(directp[cbpos*16:(cbpos+1)*16], f[:])
			encryptAESStore(string(directp[cbpos*16:(cbpos+1)*16]), HMACKey, AESKey, data[curBlock*configBlockSize:curBlock*(configBlockSize+1)])
			curBlock++
			cbpos++
		}
		encryptAESStore(file.IndirectP, HMACKey, AESKey, directp)
	}
	if curBlock == blockCount {
		return nil
	}
	if cbpos == 256 {
		f := uuid.New()
		file.DoubleIndirectP = string(f[:])
		encryptAESStore(file.DoubleIndirectP, HMACKey, AESKey, make([]byte, 256*16))
	}
	cbpos -= 256
	doubleIndirectP, err := decryptAESLoad(file.DoubleIndirectP, HMACKey, AESKey)
	if err != nil {
		return err
	}
	for curBlock < blockCount {
		dpos := cbpos / 256
		if cbpos%256 == 0 {
			f := uuid.New()
			copy(doubleIndirectP[dpos*16:(dpos+1)*16], f[:])
			encryptAESStore(string(doubleIndirectP[dpos*16:(dpos+1)*16]), HMACKey, AESKey, make([]byte, 256*16))
		}
		indirectP, err := decryptAESLoad(string(doubleIndirectP[dpos*16:(dpos+1)*16]), HMACKey, AESKey)
		if err != nil {
			return err
		}
		for curBlock < blockCount && cbpos%256 != 0 {
			fpos := cbpos % 256
			f := uuid.New()
			copy(indirectP[fpos:fpos+16], f[:])
			encryptAESStore(string(f[:]), HMACKey, AESKey, data[curBlock*configBlockSize:(curBlock+1)*configBlockSize])
			curBlock++
			cbpos++
		}
		encryptAESStore(string(doubleIndirectP[dpos*16:(dpos+1)*16]), HMACKey, AESKey, indirectP)
	}
	encryptAESStore(file.DoubleIndirectP, HMACKey, AESKey, doubleIndirectP)
	return nil

}

func (file *fileInode) Store(data []byte, HMACKey []byte, AESKey []byte) (err error) {
	file.CurBlock = 0
	err = file.Append(data, HMACKey, AESKey)
	return

}

func encryptRSAStore(key string, HMACKey []byte, username string, data []byte) (err error) {
	RSAPubKey, ok := userlib.KeystoreGet(username)
	if !ok {
		err = errors.New("RSA key not set for the user")
		return
	}
	data, err = userlib.RSAEncrypt(&RSAPubKey, data, nil)
	if err != nil {
		return
	}
	h := userlib.NewHMAC(HMACKey)
	h.Write(data)
	hmacSign := h.Sum(nil)
	userlib.DatastoreSet(key, append(data, hmacSign...))
	return
}

func decryptRSALoad(key string, HMACKey []byte, RSAPrivKey *userlib.PrivateKey) (data []byte, err error) {
	data, ok := userlib.DatastoreGet(key)
	if data == nil {
		return
	}
	if !ok {
		err = errors.New("Nothing at the key")
		return
	}
	hmacSign0 := data[len(data)-userlib.HashSize:]
	h := userlib.NewHMAC(HMACKey)
	h.Write(data[:len(data)-userlib.HashSize])
	hmacSign1 := h.Sum(nil)
	if !userlib.Equal(hmacSign0, hmacSign1) {
		err = errors.New("Data compromised")
		return
	}
	data, err = userlib.RSADecrypt(RSAPrivKey, data[:len(data)-userlib.HashSize], nil)
	return
}

// StoreFile : function used to create a  file
// It should store the file in blocks only if length
// of data []byte is a multiple of the blocksize; if
// this is not the case, StoreFile should return an error.
func (userdata *User) StoreFile(filename string, data []byte) (err error) {
	username := userdata.Username
	if len(data)%configBlockSize != 0 {
		err = errors.New("Datasize not multiple of configBlockSize")
		return
	}
	userPubKey, ok := userlib.KeystoreGet(username)
	if !ok {
		err = errors.New("Public key not set for given user") //Handle with suitable error
		return
	}
	encFileName, err := userlib.RSAEncrypt(&userPubKey, []byte(filename), nil) //Check if we want to assign some label instead of nil
	if err != nil {
		return
	}
	h := userlib.NewSHA256()
	h.Write([]byte(username + string(encFileName)))
	datastoreKey := h.Sum(nil)
	HMACKey := userlib.Argon2Key([]byte(username+filename), []byte(filename), uint32(userlib.HashSize))
	sharingRecordKey, err := decryptRSALoad(string(datastoreKey), HMACKey, userdata.RSAPrivateKey)
	if err != nil {
		return
	}
	if sharingRecordKey == nil {
		//File is getting stored first time.
		f := uuid.New()
		sharingRecordHMACKey := userlib.RandomBytes(userlib.HashSize)
		value := []byte(string(f[:]) + string(sharingRecordHMACKey))
		value, err = userlib.RSAEncrypt(&userPubKey, value, nil)
		hmac0 := userlib.NewHMAC(HMACKey)
		hmac0.Write(value)
		hmacValue := hmac0.Sum(nil)
		userlib.DatastoreSet(string(datastoreKey), append(value, hmacValue...))

		//Now write sharing record
		fileLocation := userlib.Argon2Key([]byte(username+filename), []byte(userdata.PasswordHash), 16)
		fileAESKey := userlib.Argon2Key([]byte(fileLocation), []byte(userdata.PasswordHash), uint32(userlib.AESKeySize))
		fileHMACKey := userlib.Argon2Key([]byte(fileAESKey), []byte(userdata.PasswordHash), uint32(userlib.HashSize))

		encFileName, err1 := userlib.RSAEncrypt(&userPubKey, []byte(filename), nil)
		err = err1
		if err1 != nil {
			return
		}
		encFileLocation, err1 := userlib.RSAEncrypt(&userPubKey, []byte(fileLocation), nil)
		err = err1
		if err != nil {
			return
		}
		encFileAESKey, err1 := userlib.RSAEncrypt(&userPubKey, []byte(fileAESKey), nil)
		err = err1
		if err != nil {
			return
		}
		encFileHMACKey, err1 := userlib.RSAEncrypt(&userPubKey, []byte(fileHMACKey), nil)
		err = err1
		if err != nil {
			return
		}

		sharingRecord := sharingRecord{}
		sharingRecord.Owner = userdata.Username
		sharingRecord.MUser[userdata.Username] = fileMetaData{string(encFileName), string(encFileAESKey), string(encFileHMACKey), string(encFileLocation)}
		js, err1 := json.Marshal(sharingRecord)
		err = err1
		if err != nil {
			return
		}
		userlib.DatastoreSet(string(f[:]), []byte(string(js)))

		fileInode := fileInode{}
		fileInode.CurBlock = 0
		js, err1 = json.Marshal(fileInode)
		err = err1
		if err != nil {
			return
		}
		js = []byte(string(js))
		encryptAESStore(string(fileLocation), fileHMACKey, fileAESKey, js)
		fileInode.Store(data, fileHMACKey, fileAESKey)

	} else {
		sharingRecordJsonByte, ok := userlib.DatastoreGet(string(sharingRecordKey))
		if !ok {
			err = errors.New("Error in fetching data from datastore")
			return
		}
		var sharingRecord sharingRecord
		err = json.Unmarshal(sharingRecordJsonByte, &sharingRecord)
		if err != nil {
			return
		}
		fileLocation, err1 := userlib.RSADecrypt(userdata.RSAPrivateKey, []byte((sharingRecord.MUser[userdata.Username]).EncLocation), nil)
		err = err1
		if err != nil {
			return
		}
		fileHMACKey, err1 := userlib.RSADecrypt(userdata.RSAPrivateKey, []byte((sharingRecord.MUser[userdata.Username]).EncHMACKey), nil)
		err = err1
		if err != nil {
			return
		}
		fileAESKey, err1 := userlib.RSADecrypt(userdata.RSAPrivateKey, []byte((sharingRecord.MUser[userdata.Username]).EncAESKey), nil)
		err = err1
		if err != nil {
			return
		}
		fileInodeJsonBytes, err1 := decryptAESLoad(string(fileLocation), fileHMACKey, fileAESKey)
		err = err1
		if err != nil {
			return
		}
		var fileInode fileInode
		err = json.Unmarshal(fileInodeJsonBytes, &fileInode)
		if err != nil {
			return
		}
		err = fileInode.Store(data, fileHMACKey, fileAESKey)
	}

	return nil
}

//
// Append should be efficient, you shouldn't rewrite or reencrypt the
// existing file, but only whatever additional information and
// metadata you need. The length of data []byte must be a multiple of
// the block size; if it is not, AppendFile must return an error.
// AppendFile : Function to append the file
func (userdata *User) AppendFile(filename string, data []byte) (err error) {
	username := userdata.Username
	if len(data)%configBlockSize != 0 {
		return errors.New("Datasize not multiple of configBlockSize")
	}
	userPubKey, ok := userlib.KeystoreGet(username)
	if !ok {
		panic("Public key not set for given user") //Handle with suitable error
	}
	encFileName, err := userlib.RSAEncrypt(&userPubKey, []byte(filename), nil) //Check if we want to assign some label instead of nil
	if err != nil {
		panic(err)
	}
	h := userlib.NewSHA256()
	h.Write([]byte(username + string(encFileName)))
	datastoreKey := h.Sum(nil)
	HMACKey := userlib.Argon2Key([]byte(username+filename), []byte(filename), uint32(userlib.HashSize))
	sharingRecordKey, err := decryptRSALoad(string(datastoreKey), HMACKey, userdata.RSAPrivateKey)
	if err != nil {
		return err
	}
	if sharingRecordKey == nil {
		//File is getting stored first time.
		f := uuid.New()
		sharingRecordHMACKey := userlib.RandomBytes(userlib.HashSize)
		value := []byte(string(f[:]) + string(sharingRecordHMACKey))
		value, err = userlib.RSAEncrypt(&userPubKey, value, nil)
		hmac0 := userlib.NewHMAC(HMACKey)
		hmac0.Write(value)
		hmacValue := hmac0.Sum(nil)
		userlib.DatastoreSet(string(datastoreKey), append(value, hmacValue...))

		//Now write sharing record
		fileLocation := userlib.Argon2Key([]byte(username+filename), []byte(userdata.PasswordHash), 16)
		fileAESKey := userlib.Argon2Key([]byte(fileLocation), []byte(userdata.PasswordHash), uint32(userlib.AESKeySize))
		fileHMACKey := userlib.Argon2Key([]byte(fileAESKey), []byte(userdata.PasswordHash), uint32(userlib.HashSize))

		encFileName, err := userlib.RSAEncrypt(&userPubKey, []byte(filename), nil)
		if err != nil {
			return err
		}
		encFileLocation, err := userlib.RSAEncrypt(&userPubKey, []byte(fileLocation), nil)
		if err != nil {
			return err
		}
		encFileAESKey, err := userlib.RSAEncrypt(&userPubKey, []byte(fileAESKey), nil)
		if err != nil {
			return err
		}
		encFileHMACKey, err := userlib.RSAEncrypt(&userPubKey, []byte(fileHMACKey), nil)
		if err != nil {
			return err
		}

		sharingRecord := sharingRecord{}
		sharingRecord.Owner = userdata.Username
		sharingRecord.MUser[userdata.Username] = fileMetaData{string(encFileName), string(encFileAESKey), string(encFileHMACKey), string(encFileLocation)}
		js, err := json.Marshal(sharingRecord)
		if err != nil {
			return err
		}
		userlib.DatastoreSet(string(f[:]), []byte(string(js)))

		fileInode := fileInode{}
		fileInode.CurBlock = 0
		js, err = json.Marshal(fileInode)
		if err != nil {
			return err
		}
		js = []byte(string(js))
		encryptAESStore(string(fileLocation), fileHMACKey, fileAESKey, js)
		fileInode.Store(data, fileHMACKey, fileAESKey)

	} else {
		sharingRecordJsonByte, ok := userlib.DatastoreGet(string(sharingRecordKey))
		if !ok {
			return errors.New("Error in fetching data from datastore")
		}
		var sharingRecord sharingRecord
		err := json.Unmarshal(sharingRecordJsonByte, &sharingRecord)
		if err != nil {
			return err
		}
		fileLocation, err := userlib.RSADecrypt(userdata.RSAPrivateKey, []byte((sharingRecord.MUser[userdata.Username]).EncLocation), nil)
		if err != nil {
			return err
		}
		fileHMACKey, err := userlib.RSADecrypt(userdata.RSAPrivateKey, []byte((sharingRecord.MUser[userdata.Username]).EncHMACKey), nil)
		if err != nil {
			return err
		}
		fileAESKey, err := userlib.RSADecrypt(userdata.RSAPrivateKey, []byte((sharingRecord.MUser[userdata.Username]).EncAESKey), nil)
		if err != nil {
			return err
		}
		fileInodeJsonBytes, err := decryptAESLoad(string(fileLocation), fileHMACKey, fileAESKey)
		if err != nil {
			return err
		}
		var fileInode fileInode
		err = json.Unmarshal(fileInodeJsonBytes, &fileInode)
		if err != nil {
			return err
		}
		err = fileInode.Append(data, fileHMACKey, fileAESKey)

		//
	}

	return
}

// LoadFile :This loads a block from a file in the Datastore.
//
// It should give an error if the file block is corrupted in any way.
// If there is no error, it must return exactly one block (of length blocksize)
// of data.
//
// LoadFile is also expected to be efficient. Reading a random block from the
// file should not fetch more than O(1) blocks from the Datastore.
func (userdata *User) LoadFile(filename string, offset int) (data []byte, err error) {
	username := userdata.Username
	userPubKey, ok := userlib.KeystoreGet(username)
	if !ok {
		panic("Public key not set for given user") //Handle with suitable error
	}
	encFileName, err := userlib.RSAEncrypt(&userPubKey, []byte(filename), nil) //Check if we want to assign some label instead of nil
	if err != nil {
		panic(err)
	}
	h := userlib.NewSHA256()
	h.Write([]byte(username + string(encFileName)))
	datastoreKey := h.Sum(nil)
	HMACKey := userlib.Argon2Key([]byte(username+filename), []byte(filename), uint32(userlib.HashSize))
	sharingRecordKey, err := decryptRSALoad(string(datastoreKey), HMACKey, userdata.RSAPrivateKey)
	if sharingRecordKey == nil || err != nil {
		err = errors.New("No such file exists")
		return
	}
	sharingRecordJsonByte, ok := userlib.DatastoreGet(string(sharingRecordKey))
	if !ok {
		err = errors.New("Error in fetching data from datastore")
		return
	}
	var sharingRecord sharingRecord
	err = json.Unmarshal(sharingRecordJsonByte, &sharingRecord)
	if err != nil {
		return
	}
	_, ok = sharingRecord.MUser[userdata.Username]
	if !ok {
		err = errors.New("Data compromised")
		return
	}
	fileLocation, err := userlib.RSADecrypt(userdata.RSAPrivateKey, []byte((sharingRecord.MUser[userdata.Username]).EncLocation), nil)
	if err != nil {
		return
	}
	fileHMACKey, err := userlib.RSADecrypt(userdata.RSAPrivateKey, []byte((sharingRecord.MUser[userdata.Username]).EncHMACKey), nil)
	if err != nil {
		return
	}
	fileAESKey, err := userlib.RSADecrypt(userdata.RSAPrivateKey, []byte((sharingRecord.MUser[userdata.Username]).EncAESKey), nil)
	if err != nil {
		return
	}
	fileInodeJsonBytes, err := decryptAESLoad(string(fileLocation), fileHMACKey, fileAESKey)
	if err != nil {
		return
	}
	var fileInode fileInode
	err = json.Unmarshal(fileInodeJsonBytes, &fileInode)
	if err != nil {
		return
	}
	data, err = fileInode.Load(offset, fileHMACKey, fileAESKey)
	return
}

// ShareFile : Function used to the share file with other user
func (userdata *User) ShareFile(filename string, recipient string) (msgid string, err error) {
	return "ad", nil
}

// ReceiveFile:Note recipient's filename can be different from the sender's filename.
// The recipient should not be able to discover the sender's view on
// what the filename even is!  However, the recipient must ensure that
// it is authentically from the sender.
// ReceiveFile : function used to receive the file details from the sender
func (userdata *User) ReceiveFile(filename string, sender string, msgid string) error {
	return nil
}

// RevokeFile : function used revoke the shared file access
func (userdata *User) RevokeFile(filename string) (err error) {
	return nil
}

// This creates a sharing record, which is a key pointing to something
// in the datastore to share with the recipient.

// This enables the recipient to access the encrypted file as well
// for reading/appending.

// Note that neither the recipient NOR the datastore should gain any
// information about what the sender calls the file.  Only the
// recipient can access the sharing record, and only the recipient
// should be able to know the sender.
// You may want to define what you actually want to pass as a
// sharingRecord to serialized/deserialize in the data store.

type fileMetaData struct {
	EncFileName string
	EncAESKey   string
	EncHMACKey  string
	EncLocation string
}

type sharingRecord struct {
	Owner string
	MUser map[string]fileMetaData
}

// This creates a user.  It will only be called once for a user
// (unless the keystore and datastore are cleared during testing purposes)

// It should store a copy of the userdata, suitably encrypted, in the
// datastore and should store the user's public key in the keystore.

// The datastore may corrupt or completely erase the stored
// information, but nobody outside should be able to get at the stored
// User data: the name used in the datastore should not be guessable
// without also knowing the password and username.
// You are not allowed to use any global storage other than the
// keystore and the datastore functions in the userlib library.

// You can assume the user has a STRONG password

//InitUser : function used to create user
func InitUser(username string, password string) (userdataptr *User, err error) {
	// Initialize a new User struct
	user := User{}
	// assign user properties to User struct variables
	user.Username = username

	// generate password hash
	h := userlib.NewSHA256()
	h.Write([]byte(password))
	hashedPassword := string(h.Sum(nil))
	h = userlib.NewSHA256()
	h.Write([]byte(hashedPassword + username))

	// set password hash and RSAPrivateKey in User struct
	user.PasswordHash = h.Sum(nil)
	user.RSAPrivateKey, err = userlib.GenerateRSAKey()

	// encode User struct into a json object
	userJson, err := json.Marshal(user)
	if err != nil {
		panic(err)
	}

	// convert json to string
	userString := string(userJson)
	// convert string to byte slice
	text := []byte(userString)

	//
	AESKey := userlib.Argon2Key([]byte(password), []byte(username), uint32(userlib.AESKeySize))
	dataStoreKey := string(userlib.Argon2Key(AESKey, []byte(username), uint32(userlib.AESKeySize)))

	cipherText := make([]byte, userlib.BlockSize+len(text))

	copy(cipherText[:userlib.BlockSize], userlib.RandomBytes(userlib.BlockSize))

	stream := userlib.CFBEncrypter(AESKey, cipherText[:userlib.BlockSize])
	stream.XORKeyStream(cipherText[userlib.BlockSize:], text)

	userlib.DatastoreSet(dataStoreKey, cipherText)

	return &user, nil
}

// GetUser : This fetches the user information from the Datastore.  It should
// fail with an error if the user/password is invalid, or if the user
// data was corrupted, or if the user can't be found.
//GetUser : function used to get the user details
func GetUser(username string, password string) (userdataptr *User, err error) {
	return nil, nil
}
