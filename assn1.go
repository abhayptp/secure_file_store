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
	Username       string
	PasswordHash   []byte
	RSAPrivateKey  *userlib.PrivateKey
	FileNameEncKey []byte

	// You can add other fields here if you want...
	// Note for JSON to marshal/unmarshal, the fields need to
	// be public (start with a capital letter)
}

type fileInode struct {
	CurBlock        int
	DirectP         [10][]byte
	IndirectP       []byte
	DoubleIndirectP []byte
}

func Hash(data []byte) (result []byte) {
	h := userlib.NewSHA256()
	h.Write(data)
	result = h.Sum(nil)
	return
}

func verifyHMACSign(data []byte, key []byte, HMACkey []byte) (data1 []byte, check bool) {
	if len(data)<userlib.HashSize{
		return nil, false
	}
	data1 = data[:len(data)-userlib.HashSize]
	hmacVal0 := data[len(data)-userlib.HashSize:]

	data2 := make([]byte, len(data1))
	copy(data2, data1)
	data2 = append(data2, key...)

	h := userlib.NewHMAC(HMACkey)
	h.Write([]byte(data2))
	hmacVal1 := h.Sum(nil)

	check = userlib.Equal(hmacVal0, hmacVal1)
	return
}

func appendHMACSign(data []byte, key []byte, HMACkey []byte) (data1 []byte) {
	h := userlib.NewHMAC(HMACkey)
	h.Write(append(data, key...))
	hmacSign := h.Sum(nil)
	data1 = append(data, hmacSign...)
	return
}

func decryptAESLoad(key string, HMACKey []byte, AESKey []byte) (data []byte, err error) {
	data, ok := userlib.DatastoreGet(key)
	if !ok || data == nil {
		err = errors.New("Not found at key")
		return
	}

	data, check := verifyHMACSign(data, []byte(key), HMACKey)
	if !check {
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


	cipherText = appendHMACSign(cipherText, []byte(key), HMACKey)
	userlib.DatastoreSet(key, cipherText)
}

func (file *fileInode) Load(offset int, HMACKey []byte, AESKey []byte) (data []byte, err error) {
	blocks := offset
	userlib.DebugMsg("hello cur block: %d %d", file.CurBlock, blocks)
	if blocks >= file.CurBlock {
		err = errors.New("Access offset greater than size of file")
		return
	}
	if blocks < 10 {
		userlib.DebugMsg("pointer %x\n", file.DirectP[blocks])
		data, err = decryptAESLoad(string(file.DirectP[blocks]), HMACKey, AESKey)
		return
	}
	blocks -= 10
	//if blocks == 0 {
	//return
	//}
	userlib.DebugMsg("hello blocks %d\n", blocks)
	if blocks < 32 {
		data, err = decryptAESLoad(string(file.IndirectP), HMACKey, AESKey)
		if err != nil {
			return
		}
		mblock := data[blocks*16 : blocks*16+16]
		data, err = decryptAESLoad(string(mblock), HMACKey, AESKey)
		return
	}
	blocks -= 32
	//if blocks == 0 {
	//return
	//}
	userlib.DebugMsg("hello load blocks %d\n", blocks)
	indblock := blocks / 32
	dirblock := blocks % 32
	data, err = decryptAESLoad(string(file.DoubleIndirectP), HMACKey, AESKey)
	userlib.DebugMsg("direct block address %x", data)

	if err != nil {
		return
	}
	indblockAdd, err := decryptAESLoad(string(data[indblock*16:indblock*16+16]), HMACKey, AESKey)
	userlib.DebugMsg("indirect block direct block %d %d\n", indblock, dirblock)
	userlib.DebugMsg("direct block address 2 %x", indblockAdd)

	if err != nil {
		return
	}
	userlib.DebugMsg("direct block pointer %x\n", indblockAdd[dirblock*16:(dirblock+1)*16])
	data, err = decryptAESLoad(string(indblockAdd[dirblock*16:(dirblock+1)*16]), HMACKey, AESKey)
	userlib.DebugMsg("direct block address 3 %x", data)

	if err != nil {
		return
	}
	//dirblockAdd, err := decryptAESLoad(string(data[dirblock*16:dirblock*16+16]), HMACKey, AESKey)
	//userlib.DebugMsg("direct block address %x", dirblockAdd)
	//if err != nil {
	//return
	//}
	//data, err = decryptAESLoad(string(dirblockAdd), HMACKey, AESKey)
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
	for curBlock < blockCount && cbpos < 10 {
		f := uuid.New()
		file.DirectP[cbpos] = f[:]
		//userlib.DebugMsg("append pointer %x", file.DirectP[cbpos])
		encryptAESStore(string(file.DirectP[cbpos]), HMACKey, AESKey, data[curBlock*configBlockSize:(curBlock+1)*(configBlockSize)])
		cbpos++
		curBlock++
	}
	file.CurBlock = cbpos
	userlib.DebugMsg("file_cur_block curBlock blockCount %d %d %d\n", file.CurBlock, curBlock, blockCount)
	if curBlock == blockCount {
		return nil
	}
	if cbpos == 10 {
		f := uuid.New()
		file.IndirectP = (f[:])
		encryptAESStore(string(file.IndirectP), HMACKey, AESKey, make([]byte, 32*16))
	}
	cbpos -= 10
	if cbpos < 32 {
		directp, err := decryptAESLoad(string(file.IndirectP), HMACKey, AESKey)
		if err != nil {
			return err
		}
		for curBlock < blockCount && cbpos < 32 {
			f := uuid.New()
			copy(directp[cbpos*16:(cbpos+1)*16], f[:])
			encryptAESStore(string(directp[cbpos*16:(cbpos+1)*16]), HMACKey, AESKey, data[curBlock*configBlockSize:(curBlock+1)*(configBlockSize)])
			curBlock++
			cbpos++
		}
		encryptAESStore(string(file.IndirectP), HMACKey, AESKey, directp)
	}
	userlib.DebugMsg("adfsf %d %d %d\n", file.CurBlock, curBlock, blockCount)
	file.CurBlock = cbpos + 10
	if curBlock == blockCount {
		return nil
	}
	userlib.DebugMsg("cbpos %d %d %d\n", cbpos, curBlock, blockCount)
	if cbpos == 32 {
		f := uuid.New()
		file.DoubleIndirectP = (f[:])
		encryptAESStore(string(file.DoubleIndirectP), HMACKey, AESKey, make([]byte, 32*16))
	}
	cbpos -= 32
	doubleIndirectP, err := decryptAESLoad(string(file.DoubleIndirectP), HMACKey, AESKey)
	if err != nil {
		return err
	}
	for curBlock < blockCount {
		dpos := cbpos / 32
		if cbpos%32 == 0 {
			f := uuid.New()
			copy(doubleIndirectP[dpos*16:(dpos+1)*16], f[:])
			encryptAESStore(string(doubleIndirectP[dpos*16:(dpos+1)*16]), HMACKey, AESKey, make([]byte, 32*16))
		}
		indirectP, err := decryptAESLoad(string(doubleIndirectP[dpos*16:(dpos+1)*16]), HMACKey, AESKey)
		if err != nil {
			return err
		}
		fpos := cbpos % 32
		f := uuid.New()
		//if cbpos%256 == 0 {
		copy(indirectP[fpos*16:(fpos+1)*16], f[:])
		encryptAESStore(string(f[:]), HMACKey, AESKey, data[curBlock*configBlockSize:(curBlock+1)*configBlockSize])
		curBlock++
		cbpos++
		//}
		userlib.DebugMsg("curBlock cbpos %d %d\n", curBlock, cbpos)
		for curBlock < blockCount && cbpos%32 != 0 {
			fpos = cbpos % 32
			f = uuid.New()
			userlib.DebugMsg("uuid %x\n", f[:])
			copy(indirectP[fpos*16:(fpos+1)*16], f[:])
			encryptAESStore(string(f[:]), HMACKey, AESKey, data[curBlock*configBlockSize:(curBlock+1)*configBlockSize])
			curBlock++
			cbpos++
		}
		userlib.DebugMsg("curBlock blockCount %d %d\n", curBlock, blockCount)
		encryptAESStore(string(doubleIndirectP[dpos*16:(dpos+1)*16]), HMACKey, AESKey, indirectP)
	}
	file.CurBlock = cbpos + 32 + 10
	userlib.DebugMsg("%s\n", "hello1")
	userlib.DebugMsg("cur block %d\n", file.CurBlock)
	encryptAESStore(string(file.DoubleIndirectP), HMACKey, AESKey, doubleIndirectP)
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
	// h := userlib.NewHMAC(HMACKey)
	// h.Write(data)
	// hmacSign := h.Sum(nil)
	data = appendHMACSign(data, []byte(key), HMACKey)
	userlib.DatastoreSet(key, data)
	return
}

func decryptRSALoad(key string, HMACKey []byte, RSAPrivKey *userlib.PrivateKey) (data []byte, err error) {
	data, ok := userlib.DatastoreGet(key)

	if !ok {
		err = errors.New("Nothing at the key")
		return
	}
	userlib.DebugMsg("decryptRSA %x", string(data))

	data, check := verifyHMACSign(data, []byte(key), HMACKey)
	if !check {
		err = errors.New("Data compromised")
		return
	}
	data, err = userlib.RSADecrypt(RSAPrivKey, data, nil)

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

	//RSA ENCRYPTION IS RANDOM. IT MEANS THAT SAME VALUE ENCRYPTED MULTIPLE TIMES WILL GIVE DIFFERENT RESULTS.
	//SO, COMMENTING BELOW LINE

	//encFileName, err := userlib.RSAEncrypt(&userPubKey, []byte(filename), nil) //Check if we want to assign some label instead of nil


	encFileName := Hash([]byte(filename))

	userlib.DebugMsg("store encFileName %x\n", encFileName)

	datastoreKey := Hash([]byte(username + string(encFileName)))
	userlib.DebugMsg("store datastore key %x", datastoreKey)

	HMACKey := userlib.Argon2Key([]byte(username+filename), []byte(userdata.PasswordHash), uint32(userlib.HashSize))
	_, ok = userlib.DatastoreGet(string(datastoreKey))

	if !ok {
		//File is getting stored first time.
		f := uuid.New()
		//userlib.DebugMsg("store sharing record key %x %d", f[:], len(f))
		sharingRecordHMACKey := userlib.RandomBytes(userlib.HashSize)
		value := []byte(string(f[:]) + string(sharingRecordHMACKey))

		err = encryptRSAStore(string(datastoreKey), HMACKey, username, value)
		if err != nil {
			return
		}

		fileLocation := userlib.Argon2Key([]byte(username+filename), []byte(userdata.PasswordHash), 16)
		//userlib.DebugMsg("store file location %x", fileLocation)
		fileAESKey := userlib.Argon2Key([]byte(fileLocation), []byte(userdata.PasswordHash), uint32(userlib.AESKeySize))
		fileHMACKey := userlib.Argon2Key([]byte(fileAESKey), []byte(userdata.PasswordHash), uint32(userlib.HashSize))

		encFileLocation, err1 := userlib.RSAEncrypt(&userPubKey, []byte(fileLocation), nil)
		//encFileLocation = []byte("aaa")
		//userlib.DebugMsg("store enclocation %x\n", encFileLocation)
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
		sharingRecord.Owner, err = userlib.RSAEncrypt(&userdata.RSAPrivateKey.PublicKey, []byte(userdata.Username), nil)
		if err!=nil {
			return err
		}
		sharingRecord.MUser = make(map[string]fileMetaData)
		ff := fileMetaData{}
		ff.EncAESKey = (encFileAESKey)
		ff.EncHMACKey = (encFileHMACKey)
		ff.EncLocation = (encFileLocation)
		ff.EncFileName = (encFileName)
		sharingRecord.MUser[userdata.Username] = ff
		//fileMetaData{string(encFileName), string(encFileAESKey), string(encFileHMACKey), string(encFileLocation)}
		js, err1 := json.Marshal(sharingRecord)
		err = err1
		if err != nil {
			return
		}
		js = []byte(string(js))
		js = appendHMACSign(js, f[:], sharingRecordHMACKey)
		//userlib.DebugMsg("store sharing key %x", js)
		userlib.DatastoreSet(string(f[:]), (js))

		fileInode := fileInode{}
		fileInode.CurBlock = 0
		js, err1 = json.Marshal(fileInode)
		err = err1
		if err != nil {
			return
		}
		js = []byte(string(js))
		encryptAESStore(string(fileLocation), fileHMACKey, fileAESKey, js)
		err = fileInode.Store(data, fileHMACKey, fileAESKey)
		if err != nil {
			return err
		}
		js, err1 = json.Marshal(fileInode)
		err = err1
		if err != nil {
			return
		}
		js = []byte(string(js))
		encryptAESStore(string(fileLocation), fileHMACKey, fileAESKey, js)

	} else {
		sharingR, err1 := decryptRSALoad(string(datastoreKey), HMACKey, userdata.RSAPrivateKey)
		err = err1
		if err != nil {
			return
		}
		//sharingR, err := decryptRSALoad(string(datastoreKey), HMACKey, userdata.RSAPrivateKey)
		sharingRecordKey := sharingR[:16]
		sharingRecordHMACKey := sharingR[16 : 16+userlib.HashSize]
		//userlib.DebugMsg("Load")
		//userlib.DebugMsg("%x ", (sharingRecordKey))
		//userlib.DebugMsg("load sharing record key %x", sharingRecordKey)

		sharingRecordJsonByte, ok := userlib.DatastoreGet(string(sharingRecordKey))

		if !ok {
			err = errors.New("Datastore compromised")
			return
		}

		sharingRecordJsonByte, check := verifyHMACSign(sharingRecordJsonByte, sharingRecordKey, sharingRecordHMACKey)
		if !check {
			err = errors.New("Data compromised")
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
		if err != nil {
			return err
		}
		js, err1 := json.Marshal(fileInode)
		err = err1
		if err != nil {
			return
		}
		js = []byte(string(js))
		encryptAESStore(string(fileLocation), fileHMACKey, fileAESKey, js)

	}

	return
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
		err = errors.New("Public key not set for given user") //Handle with suitable error
		return
	}

	encFileName := Hash([]byte(filename))
	datastoreKey := Hash([]byte(username + string(encFileName)))

	HMACKey := userlib.Argon2Key([]byte(username+filename), []byte(userdata.PasswordHash), uint32(userlib.HashSize))
	_, ok = userlib.DatastoreGet(string(datastoreKey))

	if !ok {
		//File is getting stored first time.
		f := uuid.New()
		sharingRecordHMACKey := userlib.RandomBytes(userlib.HashSize)
		value := []byte(string(f[:]) + string(sharingRecordHMACKey))
		//value, err = userlib.RSAEncrypt(&userPubKey, value, nil)
		err = encryptRSAStore(string(datastoreKey), HMACKey, username, value)
		if err != nil {
			return err
		}

		//Now write sharing record
		fileLocation := userlib.Argon2Key([]byte(username+filename), []byte(userdata.PasswordHash), 16)
		fileAESKey := userlib.Argon2Key([]byte(fileLocation), []byte(userdata.PasswordHash), uint32(userlib.AESKeySize))
		fileHMACKey := userlib.Argon2Key([]byte(fileAESKey), []byte(userdata.PasswordHash), uint32(userlib.HashSize))

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
		sharingRecord.Owner, err = userlib.RSAEncrypt(&userdata.RSAPrivateKey.PublicKey, []byte(userdata.Username), nil)
		if err!=nil {
			return err
		}
		sharingRecord.MUser = make(map[string]fileMetaData)
		ff := fileMetaData{}
		ff.EncAESKey = (encFileAESKey)
		ff.EncHMACKey = (encFileHMACKey)
		ff.EncLocation = (encFileLocation)
		ff.EncFileName = (encFileName)
		sharingRecord.MUser[userdata.Username] = ff

		//sharingRecord.MUser[userdata.Username] = fileMetaData{(encFileName), (encFileAESKey), (encFileHMACKey), (encFileLocation)}
		js, err1 := json.Marshal(sharingRecord)
		err = err1
		if err != nil {
			return
		}

		js = []byte(string(js))
		js = appendHMACSign(js, f[:], sharingRecordHMACKey)
		userlib.DatastoreSet(string(f[:]), (js))

		fileInode := fileInode{}
		fileInode.CurBlock = 0
		js, err1 = json.Marshal(fileInode)
		err = err1
		if err != nil {
			return
		}
		js = []byte(string(js))
		encryptAESStore(string(fileLocation), fileHMACKey, fileAESKey, js)
		err = fileInode.Store(data, fileHMACKey, fileAESKey)
		if err != nil {
			return
		}
		js, err = json.Marshal(fileInode)
		if err != nil {
			return
		}
		js = []byte(string(js))
		encryptAESStore(string(fileLocation), fileHMACKey, fileAESKey, js)

	} else {
		sharingR, err1 := decryptRSALoad(string(datastoreKey), HMACKey, userdata.RSAPrivateKey)
		err = err1
		if err != nil {
			return err
		}
		sharingRecordKey := sharingR[:16]
		sharingRecordHMACKey := sharingR[16 : 16+userlib.HashSize]

		sharingRecordJsonByte, ok := userlib.DatastoreGet(string(sharingRecordKey))
		if !ok {
			return errors.New("Error in fetching data from datastore")
		}
		sharingRecordJsonByte, check := verifyHMACSign(sharingRecordJsonByte, sharingRecordKey, sharingRecordHMACKey)

		if !check {
			err = errors.New("Data compromised")
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
		err = fileInode.Append(data, fileHMACKey, fileAESKey)
		if err != nil {
			return
		}
		js, err1 := json.Marshal(fileInode)
		err = err1
		if err != nil {
			return
		}
		js = []byte(string(js))
		encryptAESStore(string(fileLocation), fileHMACKey, fileAESKey, js)

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

	sharingRecord, err1 := userdata.GetSharingRecord(userdata.Username, filename)
	err = err1
	if err != nil {
		return
	}

	//userlib.DebugMsg("load owner of file %s", sharingRecord.Owner)
	_, ok := sharingRecord.MUser[userdata.Username]
	//userlib.DebugMsg("enclocation %x\n", hh.EncLocation)
	if !ok {
		err = errors.New("Data compromised")
		return
	}
	fileLocation, err := userlib.RSADecrypt(userdata.RSAPrivateKey, []byte((sharingRecord.MUser[userdata.Username]).EncLocation), nil)
	if err != nil {
		return
	}
	//userlib.DebugMsg("load file location %x", fileLocation)
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

func encryptAES(data []byte, AESKey []byte) (result []byte, err error) {
	cipherText := make([]byte, userlib.BlockSize+len(data))

	copy(cipherText[:userlib.BlockSize], userlib.RandomBytes(userlib.BlockSize))

	stream := userlib.CFBEncrypter(AESKey, cipherText[:userlib.BlockSize])
	stream.XORKeyStream(cipherText[userlib.BlockSize:], data)
	result = cipherText
	return
}

func decryptAES(data []byte, AESKey []byte) (result []byte, err error) {
	if len(data) < userlib.BlockSize {
		err = errors.New("Length of data to be decrypted is small")
		return
	}
	stream := userlib.CFBDecrypter(AESKey, data[:userlib.BlockSize])
	stream.XORKeyStream(data[userlib.BlockSize:], data[userlib.BlockSize:])
	result = (data[userlib.BlockSize:])
	return

}

func (userdata *User) GetSharingRecordMetadata(filename string) (sharingRecordKey []byte, sharingRecordHMACKey []byte, err error) {

	encFileName := Hash([]byte(filename))
	userlib.DebugMsg("load encFileName %x", encFileName)

	username := userdata.Username

	datastoreKey := Hash([]byte(username + string(encFileName)))
	userlib.DebugMsg("load datastore key %x", datastoreKey)
	HMACKey := userlib.Argon2Key([]byte(username+filename), []byte(userdata.PasswordHash), uint32(userlib.HashSize))
	sharingR, err := decryptRSALoad(string(datastoreKey), HMACKey, userdata.RSAPrivateKey)
	if err != nil {
		return
	}
	if len(sharingR)<(16+userlib.HashSize){
		err = errors.New("Invalid Sharing Record found.")
		return
	}
	sharingRecordKey = sharingR[:16]
	sharingRecordHMACKey = sharingR[16 : 16+userlib.HashSize]
	return

}

func (userdata *User) GetSharingRecord(username string, filename string) (sharingRecord sharingRecord, err error) {
	sharingRecordKey, sharingRecordHMACKey, err := userdata.GetSharingRecordMetadata(filename)

	if err != nil {
		return
	}
	//userlib.DebugMsg("load sharing record key %x", sharingRecordKey)
	sharingRecordJsonByte, ok := userlib.DatastoreGet(string(sharingRecordKey))
	if !ok {
		err = errors.New("File does not exists for given user")
		return
	}
	//userlib.DebugMsg("load sharing record %x", sharingRecordJsonByte)
	sharingRecordJsonByte, check := verifyHMACSign(sharingRecordJsonByte, sharingRecordKey, sharingRecordHMACKey)
	if !check {
		err = errors.New("Data compromised")
		return
	}

	err = json.Unmarshal(sharingRecordJsonByte, &sharingRecord)
	if err != nil {
		return
	}
	//userlib.DebugMsg("load owner of file %s", sharingRecord.Owner)
	//hh, ok := sharingRecord.MUser[userdata.Username]
	//userlib.DebugMsg("enclocation %x\n", hh.EncLocation)
	if !ok {
		err = errors.New("Data compromised")
	}
	return
}

func (userdata *User) ShareFile(filename string, recipient string) (msgid string, err error) {
	if len(filename)==0||len(recipient)==0{
		err = errors.New("Invalid filename or recipient name.")
		return
	}
	userlib.DebugMsg("lengthok")
	username := userdata.Username

	datastoreKey := Hash([]byte(username + string(Hash([]byte(filename)))))
	HMACKey := userlib.Argon2Key([]byte(username+filename), []byte(userdata.PasswordHash), uint32(userlib.HashSize))
	sharingR, err := decryptRSALoad(string(datastoreKey), HMACKey, userdata.RSAPrivateKey)
	if err!=nil{
		return
	}
	userlib.DebugMsg("length %d", (len(sharingR)))
	if len(sharingR)<(16+userlib.HashSize){
		err = errors.New("Invalid sharing record found.")
		return
	}
	sharingRecordKey := sharingR[:16]
	sharingRecordHMACKey := sharingR[16 : 16+userlib.HashSize]
	userlib.DebugMsg("length %d", (len(sharingR)))
	//userlib.DebugMsg("Load")
	//userlib.DebugMsg("load %x ", (sharingRecordKey))
	if sharingRecordKey == nil || err != nil {
		err = errors.New("No such file exists")
		return
	}
	//userlib.DebugMsg("load sharing record key %x", sharingRecordKey)
	sharingRecordJsonByte, ok := userlib.DatastoreGet(string(sharingRecordKey))
	if !ok{
		err = errors.New("Datastore compromised.")
		return
	}

	sharingRecordJsonByte, check := verifyHMACSign(sharingRecordJsonByte, sharingRecordKey, sharingRecordHMACKey)

	if !check {
		err = errors.New("Data compromised")
		return
	}

	userlib.DebugMsg("1 length %d", (len(sharingR)))

	var sharingRecord sharingRecord
	err = json.Unmarshal(sharingRecordJsonByte, &sharingRecord)
	if err != nil {
		return
	}
	//userlib.DebugMsg("load owner of file %s", sharingRecord.Owner)
	_, ok = sharingRecord.MUser[userdata.Username]
	//userlib.DebugMsg("enclocation %x\n", hh.EncLocation)
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
	//sharingRecordKey + HMACKeySharingRecord + FileEncKey + FileHMACKey +  fileLocation
	// msgId := append(sharingRecordKey, append(sharingRecordHMACKey, append(fileAESKey, append(fileHMACKey, fileLocation...)...)...)...)
	msgId := make([]byte, len(sharingRecordKey))
	copy(msgId, sharingRecordKey)
	msgId = append(msgId, sharingRecordHMACKey...)
	msgId = append(msgId, fileAESKey...)
	msgId = append(msgId, fileHMACKey...)
	msgId = append(msgId, fileLocation...)

	userPubKey, ok := userlib.KeystoreGet(recipient)
	if !ok{
		err = errors.New("Recipient does not exist in keystore.")
		return
	}
	msg, err := userlib.RSAEncrypt(&userPubKey, msgId, nil)
	if err != nil {
		return
	}
	userlib.DebugMsg("3 length %d", (len(sharingR)))
	sign, err := userlib.RSASign(userdata.RSAPrivateKey, msg)
	userlib.DebugMsg("sign length %d %d", len(sign), userlib.HashSize)
	if err != nil {
		return
	}
	msgid = string(append(sign, msg...))
	userlib.DebugMsg("length %x", msgid)
	return
}

// ReceiveFile:Note recipient's filename can be different from the sender's filename.
// The recipient should not be able to discover the sender's view on
// what the filename even is!  However, the recipient must ensure that
// it is authentically from the sender.
// ReceiveFile : function used to receive the file details from the sender
func (userdata *User) ReceiveFile(filename string, sender string, msgid string) error {
	userlib.DebugMsg("ok")
	username := userdata.Username

	senderPublicKey, ok := userlib.KeystoreGet(sender)
	if !ok{
		return errors.New("Public Key not available for this user.")
	}
	if len(msgid)<8*userlib.HashSize{
		return errors.New("Shared message is invalid.")
	}
	err := userlib.RSAVerify(&senderPublicKey, []byte(msgid[8*userlib.HashSize:]), []byte(msgid[:8*userlib.HashSize]))
	if err != nil {
		return err
	}
	msg, err := userlib.RSADecrypt(userdata.RSAPrivateKey, []byte(msgid[8*userlib.HashSize:]), nil)
	if err != nil {
		return err
	}

	if len(msg)<(32+2*userlib.HashSize+userlib.AESKeySize){
		return errors.New("Invalid Message.")
	}
	sharingRecordKey := msg[:16]
	sharingRecordHMACKey := msg[16 : 16+userlib.HashSize]
	fileAESKey := string(msg[16+userlib.HashSize : 16+userlib.HashSize+userlib.AESKeySize])
	fileHMACKey := string(msg[16+userlib.HashSize+userlib.AESKeySize : 16+2*userlib.HashSize+userlib.AESKeySize])
	fileLocation := string(msg[16+2*userlib.HashSize+userlib.AESKeySize : 32+2*userlib.HashSize+userlib.AESKeySize])

	userPubKey := userdata.RSAPrivateKey.PublicKey
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

	sharingRecordData, ok := userlib.DatastoreGet(string(sharingRecordKey))
	if !ok {
		return errors.New("Incorrect Message")
	}

	sharingRecordJsonByte, verified := verifyHMACSign(sharingRecordData, sharingRecordKey, sharingRecordHMACKey)
	if !verified {
		return errors.New("Sharing Record compromised")
	}

	var sharingRecord sharingRecord
	err = json.Unmarshal(sharingRecordJsonByte, &sharingRecord)
	if err != nil {
		return err
	}

	ff := fileMetaData{}
	ff.EncAESKey = (encFileAESKey)
	ff.EncHMACKey = (encFileHMACKey)
	ff.EncLocation = (encFileLocation)
	ff.EncFileName = (encFileName)
	sharingRecord.MUser[userdata.Username] = ff

	//sharingRecord.MUser[userdata.Username] = fileMetaData{(encFileName), (encFileAESKey), (encFileHMACKey), (encFileLocation)}
	js, err := json.Marshal(sharingRecord)
	if err != nil {
		return err
	}

	js = appendHMACSign([]byte(string(js)), sharingRecordKey, sharingRecordHMACKey)
	userlib.DatastoreSet(string(sharingRecordKey), js)

	hashedFileName := Hash([]byte(filename))
	sharingRecordUUIDkey := Hash([]byte(username + string(hashedFileName)))

	HMACKey := userlib.Argon2Key([]byte(username+filename), []byte(userdata.PasswordHash), uint32(userlib.HashSize))

	err1 := encryptRSAStore(string(sharingRecordUUIDkey), HMACKey, username, msg[:16+userlib.HashSize])
	if err1 != nil {
		return err
	}

	return nil
}

// RevokeFile : function used revoke the shared file access



func (userdata *User) RevokeFile(filename string) (err error) {
	sharingRecord, err := userdata.GetSharingRecord(userdata.Username, filename)

	if err != nil {
		return err
	}
	owner, err := userlib.RSADecrypt(userdata.RSAPrivateKey, sharingRecord.Owner, nil)
	if err!=nil || string(owner) != userdata.Username {
		err = errors.New("You are not owner of this file")
		return
	}
	ownerName := string(owner)
	userlib.DebugMsg("owner %s", ownerName)
	//Below, EncFileName denotes hash of file name
	for k, v := range sharingRecord.MUser {
		if k != ownerName {
			h1 := Hash([]byte(k + string(v.EncFileName)))
			userlib.DatastoreDelete(string(h1))
			delete(sharingRecord.MUser, k)
		}
	}

	sharingRecordKey, sharingRecordHMACKey, err := userdata.GetSharingRecordMetadata(filename)
	if err != nil {
		return
	}

	js, err := json.Marshal(sharingRecord)
	if err != nil {
		return
	}

	js = appendHMACSign([]byte(string(js)), sharingRecordKey, sharingRecordHMACKey)

	userlib.DatastoreSet(string(sharingRecordKey), (js))
	return
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
	EncFileName []byte
	EncAESKey   []byte
	EncHMACKey  []byte
	EncLocation []byte
}

type sharingRecord struct {
	Owner []byte
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
	if len(username) == 0 || len(password) == 0 {
		err = errors.New("Username or password length is 0")
		return
	}

	_, ok := userlib.KeystoreGet(username)
	if ok{
		err := errors.New("User already exists.")
		return nil, err
	}

	user := User{}
	// assign user properties to User struct variables
	user.Username = username

	// generate password hash
	hashedPassword := string(Hash([]byte(password)))

	// set password hash and RSAPrivateKey in User struct
	user.PasswordHash = Hash([]byte(hashedPassword + username))
	user.RSAPrivateKey, err = userlib.GenerateRSAKey()
	if err != nil {
		return
	}

	user.FileNameEncKey = userlib.Argon2Key([]byte(password), []byte(username), uint32(userlib.AESKeySize))

	userlib.KeystoreSet(username, user.RSAPrivateKey.PublicKey)

	// encode User struct into a json object
	userJson, err := json.Marshal(user)
	if err != nil {
		return
	}

	// convert json to string
	userString := string(userJson)
	// convert string to byte slice
	text := []byte(userString)

	//
	AESKey := userlib.Argon2Key([]byte(password), []byte(user.PasswordHash), uint32(userlib.AESKeySize))
	HMACKey := userlib.Argon2Key(AESKey, []byte(user.PasswordHash), uint32(userlib.HashSize))
	dataStoreKey := string(userlib.Argon2Key(HMACKey, []byte(user.PasswordHash), uint32(userlib.AESKeySize)))

	encryptAESStore(dataStoreKey, HMACKey, AESKey, text)

	return &user, nil
}

// GetUser : This fetches the user information from the Datastore.  It should
// fail with an error if the user/password is invalid, or if the user
// data was corrupted, or if the user can't be found.
//GetUser : function used to get the user details
func GetUser(username string, password string) (userdataptr *User, err error) {
	if len(username)==0|| len(password)==0{
		err = errors.New("Username or password not provided.")
		return
	}
	hashedPassword := string(Hash([]byte(password)))
	PasswordHash := Hash([]byte(hashedPassword + username))

	AESKey := userlib.Argon2Key([]byte(password), []byte(PasswordHash), uint32(userlib.AESKeySize))
	HMACKey := userlib.Argon2Key(AESKey, []byte(PasswordHash), uint32(userlib.HashSize))
	dataStoreKey := string(userlib.Argon2Key(HMACKey, []byte(PasswordHash), uint32(userlib.AESKeySize)))

	userJsonBytes, err := decryptAESLoad(dataStoreKey, HMACKey, AESKey)
	if err != nil {
		return
	}
	err = json.Unmarshal(userJsonBytes, &userdataptr)
	if err != nil {
		return
	}
	if userdataptr.Username != username {
		err = errors.New("Wrong username and password")
	}
	return
}
