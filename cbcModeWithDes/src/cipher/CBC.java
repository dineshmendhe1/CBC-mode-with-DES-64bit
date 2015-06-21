package cipher;

import java.util.*;
/**
 * CBC will override the all methods present in BlockCipherMode Interface.
 * @author Dinesh Mendhe
 */
public class CBC implements BlockCipherMode {

	BlockCipher blockCipher;
	byte iv[] = new byte[8];

	public CBC(BlockCipher blockCipher) {
		this.blockCipher = blockCipher;
	}

	/**
	 * Set the initialization vector to the given value.
	 * @param iv
	 * the initialization vector Override the method of
	 * BlockCipherMode interface.
	 */
	@Override
	public void setIV(byte[] iv) {
		this.iv = iv;
	}

	/**
	 * Set the initialization vector to a random value. Override the method of
	 * BlockCipherMode interface.
	 */
	@Override
	public void randomIV() {
		Random rand;
		int seedNo = 255; // to generate value in that particular range.(2^7= 256)
		int sValue = 0;
		rand = new Random();
		while (sValue < 8) {
			iv[sValue] = (byte)(rand.nextInt(seedNo));
			sValue++;
		}
	}

	/**
	 * Get the last initialization vector set or randomized.
	 * @return the initialization vector Override the method of BlockCipherMode
	 * interface.
	 */
	@Override
	public byte[] getIV() {
		return iv;
	}
	
	/**
     * Encrypt using DES, each 64 bits block of plaintext
     * using the given key.  Plaintext is padded
     * @param key the encryption key
     * @param plaintext the data to encrypt
     * @return the ciphertext encrypted with the given key
     */
	@Override
	public byte[] encrypt(byte[] key, byte[] plaintext) {
		byte[] ciphertext, Ppadded;
		int finalSize, bytesPadded, count=0;
		int len = plaintext.length;
		if (len % 8==0) {
			bytesPadded = 8;
			finalSize = len+bytesPadded+8;
		} else {
			bytesPadded = 8-len%8;
			finalSize = len+bytesPadded+8;
		}
		Ppadded = new byte[len + bytesPadded];
		ciphertext = new byte[finalSize];
		
		while(count<len){
			Ppadded[count] = plaintext[count];
			count++;
		}
		
		/**
		 * we will add one byte of 128 and 0 for remaining in Pplaintext.
		 */
		Ppadded[count++] = (byte)0x80;
		int finalLen = Ppadded.length;
		int counter = 0;
		while (count < finalLen) {
			Ppadded[count++] = (byte)0x00;
		}
		
		while (counter < iv.length){
			ciphertext[counter] = iv[counter];
			counter++;
		}

		byte[] Pi = new byte[8];
		byte[] Ci = iv;
		int l; int n = Ppadded.length/8;
		for (int i = 0; i < n; i++) {
			for (int j = i*8, k = 0; j < (i*8)+8; j++,k++) {
				Pi[k] = (byte) (Ppadded[j] ^ Ci[k]);
			}
			Ci = blockCipher.encrypt(key, Pi);
			l = i + 1;
			int j = l*8; int k=0;
			
			while(j<(l*8+8)){
				ciphertext[j] = Ci[k++];
				j++;
			}

		}

		return ciphertext;
	}
	 /**
     * Decrypt using DES multiple of 64 bits of ciphertext
     * using the given key and IV encoded in the ciphertext.
     * @param key the decryption key
     * @param ciphertext the data to decrypt
     * @return the plaintext decrypted with the given key
     */
	@Override
	public byte[] decrypt(byte[] key, byte[] ciphertext) {
		for (int i = 0; i < iv.length; i++) {
			iv[i] = ciphertext[i];
		}

		byte Ppadded[] = new byte[ciphertext.length-8];
		byte Cp[] = iv;
		byte Ci[] = new byte[8];
		byte xor[] = new byte[8];
		byte Pi[] = new byte[8];
		int n = Ppadded.length/8; int l = 8, k = 0;
		for (int i = 0; i < n; i++) {
			for (int j = 0; j < Ci.length; j++) {
				Ci[j] = ciphertext[l++];
			}
			Pi = blockCipher.decrypt(key, Ci);
			int j =0;
			while(j< Ci.length){
				xor[j] = (byte) (Pi[j] ^ Cp[j]);
				Ppadded[k++] = (byte) (xor[j]);
				j++;
			}
			Cp = Ci;Ci = new byte[8];
		}
		int len = Ppadded.length; int i = len-1;
		while ((Ppadded[i] & 0xff) != 128){
			i--;
		}
		byte[] plaintext = new byte[i];
		int m =0;
		while (m<i){
			plaintext[m] = Ppadded[m];
			m++;
		}
		
		return plaintext;
	}

	public static void main(String[] args) {
		DES blockCipher = new DES("sboxes_default");
		CBC cbc = new CBC(blockCipher);
		byte[] key = new byte[] { (byte) 0x75, (byte) 0xac, (byte) 0xc7,
								  (byte) 0x34, (byte) 0xbe, (byte) 0x57, (byte) 0xe0, (byte) 0xa4 };
		byte[] plaintext = new byte[] { (byte) 0x11, (byte) 0x12, (byte) 0x13,
							   (byte) 0x14, (byte) 0x15, (byte) 0x16, (byte) 0x17,
							   (byte) 0x18, (byte) 0x19, (byte) 0x20, (byte) 0x21,
							   (byte) 0x22, (byte) 0x23, (byte) 0x24, (byte) 0x25,
							   (byte) 0x26};// (byte) 0x27, (byte) 0x28, (byte) 0x29,
							 //  (byte) 0x30, (byte) 0x31, (byte) 0x32,(byte) 0x33, (byte) 0x34 };
		//cbc.randomIV();
		byte[] iv = new byte[] {(byte)0x44,(byte)0x66,(byte)0x22,(byte)0x44,
						(byte)0x55,(byte)0x66,(byte)0x77,(byte)0x11 };
		cbc.setIV(iv);
	
		byte[] ciphertext = cbc.encrypt(key, plaintext);
		System.out.println("");
		//System.err.println(" ");
		System.out.println("original plaintext::");
		for (byte c: plaintext){
			System.out.print(" "+c);
		}
		System.out.println(" ");
		System.out.println("After CBC mode encryption::");
		for(byte b: ciphertext){
		System.out.print(" " +b);
		
		}
		byte[] di = cbc.decrypt(key, ciphertext);
		System.out.println(" ");
		System.out.println("After decryption::");
		for (byte d : di){
		System.out.print(" " +d);
		}
		
	}
	
}
