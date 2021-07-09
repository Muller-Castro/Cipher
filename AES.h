#ifndef _AES_H_
#define _AES_H_

class AES
{
private:
  int Nb;
  int Nk;
  int Nr;

  unsigned int blockBytesLen;

  void SubBytes(unsigned char **state);

  void ShiftRow(unsigned char **state, int i, int n);    // shift row i on n positions

  void ShiftRows(unsigned char **state);

  unsigned char xtime(unsigned char b);    // multiply on x

  unsigned char mul_bytes(unsigned char a, unsigned char b);

  void MixColumns(unsigned char **state);

  void MixSingleColumn(unsigned char *r);

  void AddRoundKey(unsigned char **state, unsigned char *key);

  void SubWord(unsigned char *a);

  void RotWord(unsigned char *a);

  void XorWords(unsigned char *a, unsigned char *b, unsigned char *c);

  void Rcon(unsigned char * a, int n);

  void InvSubBytes(unsigned char **state);

  void InvMixColumns(unsigned char **state);

  void InvShiftRows(unsigned char **state);

  unsigned char* PaddingNulls(unsigned char in[], unsigned int inLen, unsigned int alignLen);
  
  unsigned int GetPaddingLength(unsigned int len);

  void KeyExpansion(unsigned char key[], unsigned char w[]);

  void EncryptBlock(unsigned char in[], unsigned char out[], unsigned  char key[]);

  void DecryptBlock(unsigned char in[], unsigned char out[], unsigned  char key[]);

  void XorBlocks(unsigned char *a, unsigned char * b, unsigned char *c, unsigned int len);

public:
  AES(int keyLen = 256);

  unsigned char *EncryptECB(unsigned char in[], unsigned int inLen, unsigned  char key[], unsigned int &outLen);

  unsigned char *DecryptECB(unsigned char in[], unsigned int inLen, unsigned  char key[]);

  unsigned char *EncryptCBC(unsigned char in[], unsigned int inLen, unsigned  char key[], unsigned char * iv, unsigned int &outLen);

  unsigned char *DecryptCBC(unsigned char in[], unsigned int inLen, unsigned  char key[], unsigned char * iv);

  unsigned char *EncryptCFB(unsigned char in[], unsigned int inLen, unsigned  char key[], unsigned char * iv, unsigned int &outLen);

  unsigned char *DecryptCFB(unsigned char in[], unsigned int inLen, unsigned  char key[], unsigned char * iv);
  
  void printHexArray (unsigned char a[], unsigned int n);


};

#endif // _AES_H_
