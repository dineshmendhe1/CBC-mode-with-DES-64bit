package cipher; 

/**
 * Interface to a block cipher.  The block size can be any number of bytes.
 * @author Dinesh Mendhe.
 */
public interface BlockCipher
{
    /**
     * Encrypt a block of plaintext using the given key.- key will be provided direction or can be generated using random function.
     * The block size is given by the array lengths.
     * The length of the key and the block must match.
     * @param key the encryption key
     * @param block the block to encrypt (plaintext)
     * @return the ciphertext encrypted with the given key
     */
    public byte[] encrypt(byte[] key, byte[] block);

    /**
     * Decrypt a block of ciphertext using the given key.
     * The block size is given by the array lengths.
     * The length of the key and the block must match.
     * @param key the decryption key
     * @param block the block to decrypt (ciphertext)
     * @return the plaintext decrypted with the given key
     */
    public byte[] decrypt(byte[] key, byte[] block);

}
