#include"aes.h"
#include"util.h"

#include<assert.h>
#include<memory.h>
#include<vector>

namespace std
{

bool decrypt_TPL_AES_CBC_IV(vector<uchar> &frame,
                            vector<uchar>::iterator &pos,
                            vector<uchar> &key,
                            uchar *iv,
                            int *num_encrypted_bytes,
                            int *num_not_encrypted_at_end)
{
    vector<uchar> buffer;

    std::string s;

    buffer.insert(buffer.end(), pos, frame.end());

    size_t num_bytes_to_decrypt = frame.end()-pos;

    uint8_t tpl_num_encr_blocks = 3; //t->tpl_num_encr_blocks

    if (tpl_num_encr_blocks)
    {
        num_bytes_to_decrypt = tpl_num_encr_blocks*16;
    }

    *num_encrypted_bytes = num_bytes_to_decrypt;
    *num_not_encrypted_at_end = buffer.size()-num_bytes_to_decrypt;


    if (key.size() == 0) return false;


    if (buffer.size() < num_bytes_to_decrypt)
    {

        num_bytes_to_decrypt = buffer.size();
    }

    // The content should be a multiple of 16 since we are using AES CBC mode.
    if (num_bytes_to_decrypt % 16 != 0)
    {
        assert (num_bytes_to_decrypt % 16 == 0);
    }

    uchar buffer_data[num_bytes_to_decrypt];
    memcpy(buffer_data, safeButUnsafeVectorPtr(buffer), num_bytes_to_decrypt);
    uchar decrypted_data[num_bytes_to_decrypt];
    memcpy(decrypted_data, buffer_data,num_bytes_to_decrypt);

    //AES_CBC_decrypt_buffer(decrypted_data, buffer_data, num_bytes_to_decrypt, safeButUnsafeVectorPtr(aeskey), iv);
    //void AES_CBC_decrypt_buffer(uint8_t* output, uint8_t* input, uint32_t length, const uint8_t* key, const uint8_t* iv)

    struct AES_ctx ctx;
    AES_init_ctx_iv(&ctx, &key[0], iv);
    //void AES_CBC_decrypt_buffer(struct AES_ctx* ctx, uint8_t* buf, size_t length)

    AES_CBC_decrypt_buffer(&ctx, decrypted_data, num_bytes_to_decrypt);


    // Remove the encrypted bytes.
    frame.erase(pos, frame.end());

    // Insert the decrypted bytes.
    //frame.insert(frame.end(), decrypted_data, decrypted_data+num_bytes_to_decrypt);
    frame.insert(frame.end(), decrypted_data, decrypted_data+num_bytes_to_decrypt);

    if (num_bytes_to_decrypt < buffer.size())
    {
        frame.insert(frame.end(), buffer.begin()+num_bytes_to_decrypt, buffer.end());
    }
    return true;
}


}// namespace std
