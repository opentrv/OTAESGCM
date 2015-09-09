#include <aes128_gcm.h>

void setup() {
  // put your setup code here, to run once:
  const uint8_t key[16] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
  uint8_t iv[12];
  uint8_t pdata[30];
  uint8_t adata[4];
  uint8_t tag[16];
  uint8_t cdata[30];

  aes128_gcm_encrypt(key, iv, pdata, sizeof(pdata), adata, sizeof(adata), cdata, tag);
  
  aes128_gcm_decrypt(key, iv, cdata, sizeof(cdata), adata, sizeof(adata), tag, pdata);
}

void loop() {
  // put your main code here, to run repeatedly:

}
