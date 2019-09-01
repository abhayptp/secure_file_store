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

type fileINode struct {
	CurBlock        int
	DirectP         [10][]byte
	IndirectP       []byte
	DoubleIndirectP []byte
}

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

func Hash(data []byte) (result []byte) {
	// generate Hash of data
	h := userlib.NewSHA256()
	h.Write(data)
	result = h.Sum(nil)
	return
}


func appendHMACSign(data []byte, key []byte, HMACkey []byte) (data1 []byte) {

	// generate a new signature on (data + datastore-key)
	h := userlib.NewHMAC(HMACkey)
	h.Write(append(data, key...))
	hmacSign := h.Sum(nil)
	// append it to data
	data1 = append(data, hmacSign...)
	return
}


func verifyHMACSign(data []byte, key []byte, HMACkey []byte) (data1 []byte, check bool) {
	// as HMAC signature is appended to data
	// data's length should not be less than HMAC signature length
	if len(data)<userlib.HashSize{
		return nil, false
	}
	// get the data and signature separate
	data1 = data[:len(data)-userlib.HashSize]
	hmacVal0 := data[len(data)-userlib.HashSize:]

	// generate a new slice data2 of size same as data and copy the content of data in it
	data2 := make([]byte, len(data1))
	copy(data2, data1)

	// append the datastore key to it
	data2 = append(data2, key...)


	// generate HMAC signature
	h := userlib.NewHMAC(HMACkey)
	h.Write([]byte(data2))
	hmacVal1 := h.Sum(nil)

	// verify if they are equal or not
	check = userlib.Equal(hmacVal0, hmacVal1)
	return
}

func encryptAESStore(key string, HMACKey []byte, AESKey []byte, data []byte) {

	// create a cipherText slice of length equal to (len of data + len of Initial Vector) because IV is getting prepended to data
	cipherText := make([]byte, userlib.BlockSize+len(data))

	// randomly generate IV and store it in front part of cipherText
	copy(cipherText[:userlib.BlockSize], userlib.RandomBytes(userlib.BlockSize))

	// encrypt the data to back part of cipherText
	stream := userlib.CFBEncrypter(AESKey, cipherText[:userlib.BlockSize])
	stream.XORKeyStream(cipherText[userlib.BlockSize:], data)


	//append HMAC signature to cipherText and store it in datastore
	cipherText = appendHMACSign(cipherText, []byte(key), HMACKey)
	userlib.DatastoreSet(key, cipherText)
}


func decryptAESLoad(key string, HMACKey []byte, AESKey []byte) (data []byte, err error) {

	// get the data from datastore
	data, ok := userlib.DatastoreGet(key)
	if !ok || data == nil {
		err = errors.New("Not found at key")
		return
	}

	// verify HMAC signature
	data, check := verifyHMACSign(data, []byte(key), HMACKey)
	if !check {
		err = errors.New("Data compromised")
		return
	}
	// create CFBDecrypter stream by providing AESKey and Initial Vector(which is prepended to data)
	stream := userlib.CFBDecrypter(AESKey, data[:userlib.BlockSize])
	// decrypt the data
	stream.XORKeyStream(data[userlib.BlockSize:], data[userlib.BlockSize:])
	data = (data[userlib.BlockSize:])
	return
}

func encryptRSAStore(key string, HMACKey []byte, username string, data []byte) (err error) {

	// get public key from KeyStore
	RSAPubKey, ok := userlib.KeystoreGet(username)
	if !ok {
		err = errors.New("RSA key not set for the user")
		return
	}
	// encrypt the data using public key
	data, err = userlib.RSAEncrypt(&RSAPubKey, data, nil)
	if err != nil {
		return
	}

	// append HMAC signature to the encrypted data
	data = appendHMACSign(data, []byte(key), HMACKey)
	// store the data in datastore
	userlib.DatastoreSet(key, data)
	return
}

func decryptRSALoad(key string, HMACKey []byte, RSAPrivKey *userlib.PrivateKey) (data []byte, err error) {

	// get the data from datastore
	data, ok := userlib.DatastoreGet(key)

	if !ok {
		err = errors.New("Nothing at the key")
		return
	}
	// verify HMAC signature
	data, check := verifyHMACSign(data, []byte(key), HMACKey)
	if !check {
		err = errors.New("Data compromised")
		return
	}

	// decrypt the verified data
	data, err = userlib.RSADecrypt(RSAPrivKey, data, nil)

	return
}

func (userdata *User)SetFileInfo(filename string)(fileInode fileINode, fileLocation []byte,fileHMACKey []byte, fileAESKey []byte, err error){

	// generate a new uuid to be used as sharingRecord Key
	f := uuid.New()

	// randomly generate sharingRecordHMACKey
	sharingRecordHMACKey := userlib.RandomBytes(userlib.HashSize)

	// sharingRecordMetaData
	value := []byte(string(f[:]) + string(sharingRecordHMACKey))

	// generate sharingRecordMetaData's datastore Key and HMAC Key
	datastoreKey := Hash([]byte(userdata.Username + string(Hash([]byte(filename)))))
	HMACKey := userlib.Argon2Key([]byte(userdata.Username+filename), []byte(userdata.PasswordHash), uint32(userlib.HashSize))

	// encrypt and store it in datastore
	err = encryptRSAStore(string(datastoreKey), HMACKey, userdata.Username, value)
	if err != nil {
		return
	}

	userPubKey  := userdata.RSAPrivateKey.PublicKey
	// generate file parameters using Argon2

	fileLocation = userlib.Argon2Key([]byte(userdata.Username+filename), []byte(userdata.PasswordHash), 16)
	fileAESKey = userlib.Argon2Key([]byte(fileLocation), []byte(userdata.PasswordHash), uint32(userlib.AESKeySize))
	fileHMACKey = userlib.Argon2Key([]byte(fileAESKey), []byte(userdata.PasswordHash), uint32(userlib.HashSize))

	// encrypt the parameters
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

	// create a new sharingRecord struct
	sharingRecord := sharingRecord{}
	// add owner as the current user's encrypted username
	sharingRecord.Owner, err = userlib.RSAEncrypt(&userdata.RSAPrivateKey.PublicKey, []byte(userdata.Username), nil)
	if err!=nil {
		return
	}

	// create a map to store information for all allowed users
	sharingRecord.MUser = make(map[string]fileMetaData)

	// generate fileMetaData to store information for current user
	ff := fileMetaData{}
	ff.EncAESKey = (encFileAESKey)
	ff.EncHMACKey = (encFileHMACKey)
	ff.EncLocation = (encFileLocation)
	ff.EncFileName = Hash([]byte(filename))

	// store this fileMetaData corresponding to username(key)
	sharingRecord.MUser[userdata.Username] = ff

	// marshal sharingRecord, append HMAC signature and store it in datastore
	js, err1 := json.Marshal(sharingRecord)
	err = err1
	if err != nil {
		return
	}

	js = []byte(string(js))
	js = appendHMACSign(js, f[:], sharingRecordHMACKey)
	userlib.DatastoreSet(string(f[:]), (js))


	// create fileInode for file and store it in datastore
	fileInode = fileINode{}
	fileInode.CurBlock = 0

	js, err1 = json.Marshal(fileInode)
	err = err1
	if err != nil {
		return
	}
	js = []byte(string(js))
	encryptAESStore(string(fileLocation), fileHMACKey, fileAESKey, js)
	return
}

func (userdata *User)GetFileInfo(filename string)(fileInode fileINode, fileLocation []byte,fileHMACKey []byte, fileAESKey []byte, err error){

	// get sharingRecord
	sharingRecord, err :=userdata.GetSharingRecord(filename)
	if err!=nil{
		return
	}

	// an additional check to verify that user exists in the list of allowed users
	_,ok := sharingRecord.MUser[userdata.Username]
	if !ok{
		err = errors.New("File access restricted.")
		return
	}

	// decrypt file parameters using user's PrivateKey
	fileLocation, err = userlib.RSADecrypt(userdata.RSAPrivateKey, []byte((sharingRecord.MUser[userdata.Username]).EncLocation), nil)
	if err != nil {
		return
	}
	fileHMACKey, err = userlib.RSADecrypt(userdata.RSAPrivateKey, []byte((sharingRecord.MUser[userdata.Username]).EncHMACKey), nil)
	if err != nil {
		return
	}
	fileAESKey, err = userlib.RSADecrypt(userdata.RSAPrivateKey, []byte((sharingRecord.MUser[userdata.Username]).EncAESKey), nil)
	if err != nil {
		return
	}

	// get the fileInode struct stored at fileLocation Key
	fileInodeJsonBytes, err := decryptAESLoad(string(fileLocation), fileHMACKey, fileAESKey)
	if err != nil {
		return
	}

	// unmarshal it to fileInode variable
	err = json.Unmarshal(fileInodeJsonBytes, &fileInode)

	return
}





func (file *fileINode) Store(data []byte, HMACKey []byte, AESKey []byte) (err error) {

	// reset the file currently used block count to size
	file.CurBlock = 0
	// and call append to store data from first block
	err = file.Append(data, HMACKey, AESKey)
	return
}


// StoreFile : function used to create a  file
// It should store the file in blocks only if length
// of data []byte is a multiple of the blocksize; if
// this is not the case, StoreFile should return an error.
func (userdata *User) StoreFile(filename string, data []byte) (err error) {
	username := userdata.Username
	// provided data's length should a multiple of configBlockSize
	if len(data)%configBlockSize != 0 {
		err = errors.New("Datasize not multiple of configBlockSize")
		return
	}


	//RSA ENCRYPTION IS RANDOM. IT MEANS THAT SAME VALUE ENCRYPTED MULTIPLE TIMES WILL GIVE DIFFERENT RESULTS.
	//SO, COMMENTING BELOW LINE

	// generating datastorekey as key of sharingRecordMetaData
	datastoreKey := Hash([]byte(username + string(Hash([]byte(filename)))))

	// check if shairngRecordMetaData exists at datastorekey
	_, ok := userlib.DatastoreGet(string(datastoreKey))

	if !ok {
		// sharingRecordMetaData does not exist i.e. it is being stored first time

		// generate fileInode and other parameters
		fileInode, fileLocation, fileHMACKey, fileAESKey, err := userdata.SetFileInfo(filename)
		if err!=nil{
			return err
		}

		// store the data in file
		err = fileInode.Store(data, fileHMACKey, fileAESKey)
		if err != nil {
			return err
		}

		// marshal the fileInode and store it in datastore
		js, err := json.Marshal(fileInode)
		if err != nil {
			return err
		}
		js = []byte(string(js))
		encryptAESStore(string(fileLocation), fileHMACKey, fileAESKey, js)

	} else {

		// file already exists so use GetFileInfo to get all file parameters.
		fileInode, fileLocation, fileHMACKey, fileAESKey, err :=  userdata.GetFileInfo(filename)
		if err!=nil{
			return err
		}

		// store the data in file
		err = fileInode.Store(data, fileHMACKey, fileAESKey)
		if err != nil {
			return err
		}

		// marshal the fileInode and store it in datastore
		js, err := json.Marshal(fileInode)
		if err != nil {
			return err
		}
		js = []byte(string(js))
		encryptAESStore(string(fileLocation), fileHMACKey, fileAESKey, js)
	}
	return
}

func (file *fileINode) Append(data []byte, HMACKey []byte, AESKey []byte) error {

	// provided data's length should be a multiple of configBlockSize
	if len(data)%configBlockSize != 0 {
		err := errors.New("File length not multiple of block size")
		return err
	}

	// get the total block count
	blockCount := len(data) / configBlockSize

	curBlock := 0
	//Go to current block
	//cbpos denote the block number which is yet not filled
	cbpos := file.CurBlock
	for curBlock < blockCount && cbpos < 10 {
		// for first ten pointers use uuid as pointers
		f := uuid.New()
		file.DirectP[cbpos] = f[:]
		// store the encypted data at key=uuid
		encryptAESStore(string(file.DirectP[cbpos]), HMACKey, AESKey, data[curBlock*configBlockSize:(curBlock+1)*(configBlockSize)])
		cbpos++
		curBlock++
	}
	// update the current block count of file
	file.CurBlock = cbpos

	// if data has been appended completely then return
	if curBlock == blockCount {
		return nil
	}
	// if a new indirect pointer does not exists create one
	if cbpos == 10 {
		f := uuid.New()
		file.IndirectP = (f[:])
		// store slice of zero's at new indirect pointer (getting updated later)
		encryptAESStore(string(file.IndirectP), HMACKey, AESKey, make([]byte, 32*16))
	}
	cbpos -= 10

	// fill direct pointers inside indirect pointer
	if cbpos < 32 {
		// get the data stored at indirect pointer
		directp, err := decryptAESLoad(string(file.IndirectP), HMACKey, AESKey)
		if err != nil {
			return err
		}

		// append after existing blocks
		for curBlock < blockCount && cbpos < 32 {
			// create uuid for new direct pointers inside indirect pointers
			f := uuid.New()

			// copy the uuid into directp slice at corresponding location
			copy(directp[cbpos*16:(cbpos+1)*16], f[:])
			// use this copied uuid as key and data at specific block as value and store it after encryption
			encryptAESStore(string(directp[cbpos*16:(cbpos+1)*16]), HMACKey, AESKey, data[curBlock*configBlockSize:(curBlock+1)*(configBlockSize)])
			curBlock++
			cbpos++
		}
		// update direct pointer's list under indirect pointers
		encryptAESStore(string(file.IndirectP), HMACKey, AESKey, directp)
	}

	// update the file block size
	file.CurBlock = cbpos + 10

	// if data appended completely return
	if curBlock == blockCount {
		return nil
	}
	// generate double indirect pointer
	if cbpos == 32 {
		f := uuid.New()
		file.DoubleIndirectP = (f[:])
		// create a slice of zero at double indirect pointer as key (getting updated later)
		encryptAESStore(string(file.DoubleIndirectP), HMACKey, AESKey, make([]byte, 32*16))
	}
	cbpos -= 32

	// decrypt the list of indirect pointers stored at double indirect pointer
	doubleIndirectP, err := decryptAESLoad(string(file.DoubleIndirectP), HMACKey, AESKey)
	if err != nil {
		return err
	}
	// generate new indirect pointers after existing indirect pointers
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

		copy(indirectP[fpos*16:(fpos+1)*16], f[:])
		encryptAESStore(string(f[:]), HMACKey, AESKey, data[curBlock*configBlockSize:(curBlock+1)*configBlockSize])
		curBlock++
		cbpos++

		for curBlock < blockCount && cbpos%32 != 0 {
			fpos = cbpos % 32
			f = uuid.New()
			userlib.DebugMsg("uuid %x\n", f[:])
			copy(indirectP[fpos*16:(fpos+1)*16], f[:])
			encryptAESStore(string(f[:]), HMACKey, AESKey, data[curBlock*configBlockSize:(curBlock+1)*configBlockSize])
			curBlock++
			cbpos++
		}
		encryptAESStore(string(doubleIndirectP[dpos*16:(dpos+1)*16]), HMACKey, AESKey, indirectP)
	}
	file.CurBlock = cbpos + 32 + 10

	encryptAESStore(string(file.DoubleIndirectP), HMACKey, AESKey, doubleIndirectP)
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

	// provided data's size should be a multiple of configBlockSize
	if len(data)%configBlockSize != 0 {
		return errors.New("Datasize not multiple of configBlockSize")
	}
	// check if user's public key exist in KeyStore or not
	_, ok := userlib.KeystoreGet(username)
	if !ok {
		err = errors.New("Public key not set for given user") //Handle with suitable error
		return
	}

	// generate datastoreKey for shairngRecordMetaData
	datastoreKey := Hash([]byte(username + string(Hash([]byte(filename)))))

	// check if sharingRecord exists at datastoreKey
	_, ok = userlib.DatastoreGet(string(datastoreKey))

	if !ok {
		// if sharingRecord does not exist it means the file is getting created for the first time

		// generate fileInfo and set a new sharingRecord in datastore
		fileInode, fileLocation, fileHMACKey, fileAESKey, err := userdata.SetFileInfo(filename)
		if err!=nil{
			return err
		}
		// store data in file
		err = fileInode.Store(data, fileHMACKey, fileAESKey)
		if err != nil {
			return err
		}

		js, err := json.Marshal(fileInode)
		if err != nil {
			return err
		}
		js = []byte(string(js))
		encryptAESStore(string(fileLocation), fileHMACKey, fileAESKey, js)

	} else {
		// file already exists

		// get the file info from datastore
		fileInode, fileLocation, fileHMACKey, fileAESKey, err :=  userdata.GetFileInfo(filename)
		if err!=nil{
			return err
		}
		// append data to the file
		err = fileInode.Append(data, fileHMACKey, fileAESKey)
		if err != nil {
			return err
		}
		js, err := json.Marshal(fileInode)
		if err != nil {
			return err
		}
		js = []byte(string(js))

		// encrypt fileInode using AES and store it at fileLocation
		encryptAESStore(string(fileLocation), fileHMACKey, fileAESKey, js)

		//
	}

	return
}

func (file *fileINode) Load(offset int, HMACKey []byte, AESKey []byte) (data []byte, err error) {
	blocks := offset

	// offset should not be greater than filesize
	if blocks >= file.CurBlock {
		err = errors.New("Access offset greater than size of file")
		return
	}

	// using direct pointers
	if blocks < 10 {
		data, err = decryptAESLoad(string(file.DirectP[blocks]), HMACKey, AESKey)
		return
	}
	blocks -= 10

	// indirect pointers
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

	// using Double Indirect Pointers
	indblock := blocks / 32
	dirblock := blocks % 32

	// decypt and get the list of indirect pointers
	data, err = decryptAESLoad(string(file.DoubleIndirectP), HMACKey, AESKey)
	if err != nil {
		return
	}

	// decrypt and get the list of direct pointers
	indblockAdd, err := decryptAESLoad(string(data[indblock*16:indblock*16+16]), HMACKey, AESKey)
	if err != nil {
		return
	}

	// decrypt the data
	data, err = decryptAESLoad(string(indblockAdd[dirblock*16:(dirblock+1)*16]), HMACKey, AESKey)
	if err != nil {
		return
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

	// get the file information providing filename
	fileInode, _, fileHMACKey, fileAESKey, err :=  userdata.GetFileInfo(filename)
	if err!=nil{
		return
	}
	// call Load method to get data at given offset
	data, err = fileInode.Load(offset, fileHMACKey, fileAESKey)
	return
}



func encryptAES(data []byte, AESKey []byte) (result []byte, err error) {

	// make cipherText slice of length equal to sum of lengths of Initial Vector and data
	cipherText := make([]byte, userlib.BlockSize+len(data))

	// generate Random Initial Vector and copy it in front part of cipherText
	copy(cipherText[:userlib.BlockSize], userlib.RandomBytes(userlib.BlockSize))

	// create a CFBEncrypter stream by providing AESKey and Initial Vector
	stream := userlib.CFBEncrypter(AESKey, cipherText[:userlib.BlockSize])
	// Encrypt the data to cipherText's rest part
	stream.XORKeyStream(cipherText[userlib.BlockSize:], data)
	result = cipherText
	return
}

func decryptAES(data []byte, AESKey []byte) (result []byte, err error) {
	// as Initial Vector is prepended to data
	// data's length should not be less than IV's length
	if len(data) < userlib.BlockSize {
		err = errors.New("Length of data to be decrypted is small")
		return
	}

	// provide the AESKey and IV to CFBDecrypter
	stream := userlib.CFBDecrypter(AESKey, data[:userlib.BlockSize])
	// provide data to be decrypted
	stream.XORKeyStream(data[userlib.BlockSize:], data[userlib.BlockSize:])
	result = (data[userlib.BlockSize:])
	return

}

func (userdata *User) GetSharingRecordMetadata(filename string) (sharingRecordKey []byte, sharingRecordHMACKey []byte, err error) {

	// generate key for sharingRecordMetaData using Hash of (username + Hash of filename)
	datastoreKey := Hash([]byte(userdata.Username + string(Hash([]byte(filename)))))

	// generate HMAC Key using Argon2
	HMACKey := userlib.Argon2Key([]byte(userdata.Username + filename), []byte(userdata.PasswordHash), uint32(userlib.HashSize))

	// get the decrypted metadata from datastore
	sharingR, err := decryptRSALoad(string(datastoreKey), HMACKey, userdata.RSAPrivateKey)
	if err != nil {
		return
	}

	// sharingR's length should be equal to the sum of lengths of SharingRecord Key and HMACKey
	if len(sharingR)<(16+userlib.HashSize){
		err = errors.New("Invalid Sharing Record found.")
		return
	}

	// extract sharingRecord Key and HMACKey from sharingR
	sharingRecordKey = sharingR[:16]
	sharingRecordHMACKey = sharingR[16 : 16+userlib.HashSize]
	return

}

func (userdata *User) GetSharingRecord(filename string) (sharingRecord sharingRecord, err error) {

	// call GetSharingRecordMetadata to get the sharingRecord Key and HMACKey
	sharingRecordKey, sharingRecordHMACKey, err := userdata.GetSharingRecordMetadata(filename)
	if err != nil {
		return
	}

	// get the encrypted sharingRecord from datastore using sharingRecordKey
	sharingRecordJsonByte, ok := userlib.DatastoreGet(string(sharingRecordKey))
	if !ok {
		err = errors.New("File does not exists for given user")
		return
	}

	// verify the HMAC signature
	sharingRecordJsonByte, check := verifyHMACSign(sharingRecordJsonByte, sharingRecordKey, sharingRecordHMACKey)
	if !check {
		err = errors.New("Data compromised")
		return
	}

	// unmarshal the data into sharingRecord variable
	err = json.Unmarshal(sharingRecordJsonByte, &sharingRecord)
	if err != nil {
		return
	}

	if !ok {
		err = errors.New("Data compromised")
	}
	return
}

// ShareFile : Function used to the share file with other user
func (userdata *User) ShareFile(filename string, recipient string) (msgid string, err error) {
	// validate the user input
	if len(filename)==0||len(recipient)==0{
		err = errors.New("Invalid filename or recipient name.")
		return
	}

	// generate datastorekey from Hash of (username + Hash of(filename)) and HMACKey using Argon2
	datastoreKey := Hash([]byte(userdata.Username + string(Hash([]byte(filename)))))
	HMACKey := userlib.Argon2Key([]byte(userdata.Username+filename), []byte(userdata.PasswordHash), uint32(userlib.HashSize))

	// get the sharingRecord Key and HMACKey from datastore
	sharingR, err := decryptRSALoad(string(datastoreKey), HMACKey, userdata.RSAPrivateKey)
	if err!=nil{
		return
	}

	// sharingR's length should be equal to the sum of lengths of SharingRecord Key and HMACKey
	if len(sharingR)<(16+userlib.HashSize){
		err = errors.New("Invalid sharing record found.")
		return
	}
	// extract the sharingRecord Key and HMAC Key from sharingR
	sharingRecordKey := sharingR[:16]
	sharingRecordHMACKey := sharingR[16 : 16+userlib.HashSize]

	if sharingRecordKey == nil || err != nil {
		err = errors.New("No such file exists")
		return
	}

	// get sharingRecord from DataStore
	sharingRecordJsonByte, ok := userlib.DatastoreGet(string(sharingRecordKey))
	if !ok{
		err = errors.New("Datastore compromised.")
		return
	}
	// verify HMAC Signature for sharingRecord
	sharingRecordJsonByte, check := verifyHMACSign(sharingRecordJsonByte, sharingRecordKey, sharingRecordHMACKey)
	if !check {
		err = errors.New("Data compromised")
		return
	}

	// unmarshal sharingRecord to a struct
	var sharingRecord sharingRecord
	err = json.Unmarshal(sharingRecordJsonByte, &sharingRecord)
	if err != nil {
		return
	}

	// an additional check to verify that user has access to file
	_, ok = sharingRecord.MUser[userdata.Username]
	if !ok {
		err = errors.New("Data compromised")
		return
	}

	// decrypt file information using user's PrivateKey
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

	// get public key for the recipient and encrypt the message using recipient's PublicKey
	userPubKey, ok := userlib.KeystoreGet(recipient)
	if !ok{
		err = errors.New("Recipient does not exist in keystore.")
		return
	}
	msg, err := userlib.RSAEncrypt(&userPubKey, msgId, nil)
	if err != nil {
		return
	}
	// sign the message using sender's PrivateKey
	sign, err := userlib.RSASign(userdata.RSAPrivateKey, msg)
	if err != nil {
		return
	}
	// append message to the signature
	msgid = string(append(sign, msg...))
	return
}

// ReceiveFile:Note recipient's filename can be different from the sender's filename.
// The recipient should not be able to discover the sender's view on
// what the filename even is!  However, the recipient must ensure that
// it is authentically from the sender.
// ReceiveFile : function used to receive the file details from the sender
func (userdata *User) ReceiveFile(filename string, sender string, msgid string) error {

	// message length should be greater than RSASignature length
	if len(msgid)<8*userlib.HashSize{
		return errors.New("Shared message is invalid.")
	}

	// get the sender's public key to verify the signature and also to check if that user really exists or not
	senderPublicKey, ok := userlib.KeystoreGet(sender)
	if !ok{
		return errors.New("Public Key not available for this user.")
	}

	// verify the RSASignature of the message
	err := userlib.RSAVerify(&senderPublicKey, []byte(msgid[8*userlib.HashSize:]), []byte(msgid[:8*userlib.HashSize]))
	if err != nil {
		return err
	}

	// decrypt using PrivateKey of recipient
	msg, err := userlib.RSADecrypt(userdata.RSAPrivateKey, []byte(msgid[8*userlib.HashSize:]), nil)
	if err != nil {
		return err
	}

	// the length of decrypted message should equal to the sum of the lengths of all appended parameter
	if len(msg)<(32+2*userlib.HashSize+userlib.AESKeySize){
		return errors.New("Invalid Message.")
	}
	// extract all variables from message
	sharingRecordKey := msg[:16]
	sharingRecordHMACKey := msg[16 : 16+userlib.HashSize]
	fileAESKey := string(msg[16+userlib.HashSize : 16+userlib.HashSize+userlib.AESKeySize])
	fileHMACKey := string(msg[16+userlib.HashSize+userlib.AESKeySize : 16+2*userlib.HashSize+userlib.AESKeySize])
	fileLocation := string(msg[16+2*userlib.HashSize+userlib.AESKeySize : 32+2*userlib.HashSize+userlib.AESKeySize])


	// hash the filename and encrypt other data to store it in sharingRecord
	userPubKey := userdata.RSAPrivateKey.PublicKey
	encFileName := Hash([]byte(filename))

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

	// get the sharingRecord from datastore
	sharingRecordData, ok := userlib.DatastoreGet(string(sharingRecordKey))
	if !ok {
		return errors.New("Incorrect Message")
	}
	// verify the HMAC signature
	sharingRecordJsonByte, verified := verifyHMACSign(sharingRecordData, sharingRecordKey, sharingRecordHMACKey)
	if !verified {
		return errors.New("Sharing Record compromised")
	}

	// create a new sharingRecord and unmarshal string data to sharingRecord
	var sharingRecord sharingRecord
	err = json.Unmarshal(sharingRecordJsonByte, &sharingRecord)
	if err != nil {
		return err
	}

	// put all encrypted/hashed data into fileMetaDataStruct and add this struct into MUser map of sharingRecord
	ff := fileMetaData{}
	ff.EncAESKey = (encFileAESKey)
	ff.EncHMACKey = (encFileHMACKey)
	ff.EncLocation = (encFileLocation)
	ff.EncFileName = (encFileName)
	sharingRecord.MUser[userdata.Username] = ff

	// convert it to string, append HMAC Signature and store it in datastore
	js, err := json.Marshal(sharingRecord)
	if err != nil {
		return err
	}

	js = appendHMACSign([]byte(string(js)), sharingRecordKey, sharingRecordHMACKey)
	userlib.DatastoreSet(string(sharingRecordKey), js)


	// add the sharingRecord Key and HMACKey in datastore (in encrypted format) corresponding to key=(Hash of (username + Hash of filename))
	hashedUserFile := Hash([]byte(userdata.Username + string(encFileName)))

	HMACKey := userlib.Argon2Key([]byte(userdata.Username+filename), []byte(userdata.PasswordHash), uint32(userlib.HashSize))

	err1 := encryptRSAStore(string(hashedUserFile), HMACKey, userdata.Username, msg[:16+userlib.HashSize])
	if err1 != nil {
		return err
	}

	return nil
}

// RevokeFile : function used revoke the shared file access
func (userdata *User) RevokeFile(filename string) (err error) {

	// get the sharingRecord from datastore
	sharingRecord, err := userdata.GetSharingRecord(filename)
	if err != nil {
		return err
	}
	// try to decrypt the file owner's name using user's PrivateKey
	owner, err := userlib.RSADecrypt(userdata.RSAPrivateKey, sharingRecord.Owner, nil)
	// if success and name matches with user's username then proceed
	if err!=nil || string(owner) != userdata.Username {
		err = errors.New("You are not owner of this file")
		return
	}
	ownerName := string(owner)
	//Below, EncFileName denotes hash of file name

	// Remove all user's data from sharingRecord except owner
	for k := range sharingRecord.MUser {
		if k != ownerName {
			// h1 := Hash([]byte(k + string(v.EncFileName)))
			// userlib.DatastoreDelete(string(h1))
			delete(sharingRecord.MUser, k)
		}
	}

	// get the sharingRecord Key and HMAC key to store the updated sharingRecord in datastore
	sharingRecordKey, sharingRecordHMACKey, err := userdata.GetSharingRecordMetadata(filename)
	if err != nil {
		return
	}
	// marshal the updated sharingRecord
	js, err := json.Marshal(sharingRecord)
	if err != nil {
		return
	}
	// append HMAC signature
	js = appendHMACSign([]byte(string(js)), sharingRecordKey, sharingRecordHMACKey)
	// put the updated sharingRecord in datastore
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
