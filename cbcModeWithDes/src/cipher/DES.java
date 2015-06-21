package cipher;

import java.io.*;

/**
 * Implementation of DES algorithm.
 * @author Dinesh Mendhe.
 *
 */

public class DES extends BlockCipher64{
	
	int sBoxes[][] = new int[8][64];
	
	public DES (String sBoxFileName)  {

		try 
		{
			FileInputStream file =new FileInputStream(sBoxFileName);
			BufferedInputStream buff = new BufferedInputStream(file);
			DataInputStream dataStream = new DataInputStream(buff);
			int i=0,j=0;
			while(dataStream.available()>0)
			{		
				
				byte dataByte = dataStream.readByte();
				if(i == 64) {i=0; j++;}
				int s1=(int)(dataByte >> 4);
				if(s1<0) {s1=16+s1;}
				int s2=(int)(dataByte & 15);
				if(s2<0) {s2=16+s2;}
				sBoxes[j][i++]=s1; sBoxes[j][i++]=s2;
			}
			
			dataStream.close();
		} 
		catch (IOException e) 
		{			
			System.out.printf("%s", "sBoxFile not found");
		}
		
	}

	/*
	 * Ln and Rn are Left and Right 32 bit block of data.
	 */
	public long Rn, Ln, key, data, cdPairs;
	/** 
	 * It's initial permutation. The block of message is permuted at the beginning by this permutation.
	 */
	private void IP() {
		int[] IP = { 58, 50, 42, 34, 26, 18, 10, 2,
					 60, 52, 44, 36, 28, 20, 12, 4,
					 62, 54, 46, 38, 30, 22, 14, 6,
					 64, 56, 48, 40, 32, 24, 16, 8,
					 57, 49, 41, 33, 25, 17, 9, 1, 
					 59, 51, 43, 35, 27, 19, 11, 3,
					 61, 53, 45, 37, 29, 21, 13, 5,
					 63, 55, 47, 39, 31, 23, 15, 7 };
		
		
		long helperBit = 0, p=0;
		int index = 63;
		long d = this.data;
		
		while(index >=0){
			helperBit = d >>> (64 - IP[index]);
			helperBit = (helperBit & 1) << (63 -index);
			p = p ^ helperBit;
			index--;
		}
	
		data = p;
	}
	
	/* 
	 * After initial permutation the data is divided into two halves of 32 bit.
	 */
	private void leftRightHalves() {
		Ln = data >>> 32;
		Rn = data ^ (Ln << 32);
	}

	
	/*
	 * the provided 64-bit key is permuted according to this table
	 * into a 56-bit key.
	 */

	private void to56Bit() {
		int[] PC1 = { 57, 49, 41, 33, 25, 17, 9,
					  1, 58, 50, 42, 34, 26, 18,
					  10, 2, 59, 51, 43, 35, 27,
					  19, 11, 3, 60, 52, 44, 36,
					  63, 55, 47, 39, 31, 23, 15,
					  7, 62, 54, 46, 38, 30, 22,
					  14, 6, 61, 53, 45, 37, 29,
					  21, 13, 5, 28, 20, 12, 4 };
		
		long cdPairTemp = 0;
		int index = 55;
		long key = this.key;
		long helperBit = 0;
	
		while(index >=0){
			helperBit = key >>> (64 - PC1[index]);
			helperBit = (helperBit & 1)<< (55- index);
			cdPairTemp = cdPairTemp ^ helperBit;
			index--;
			
		}
		cdPairs = cdPairTemp;
	
	}
	/*
	 * Subkey rotations or key shift. This is used to rotate the certain bit-section of the key by 
	 * either one or two bits to the left in each of the 16 steps.
	 */
	int rotations[] = { 1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1 };
	/*
	 * Generated 48- bit subkeyes  based on provided 64-bit key value by using rotations i.e. circular shift.
	 */
	private long createSubkeys(int r) {
		
		long leftHalf = cdPairs >>> 28;
		leftHalf = (leftHalf << r) | (leftHalf >>> (28 - r));
		leftHalf = leftHalf & 0xFFFFFFFL;

		long rightHalf = cdPairs & 0xFFFFFFFL;
		rightHalf = (rightHalf << r) | (rightHalf >>> (28 - r));
		rightHalf = rightHalf & 0xFFFFFFFL;
		cdPairs = leftHalf << 28;
		cdPairs = cdPairs ^ rightHalf;
		
		
		/*
		 * This PC2 permutation is used to transform its running 56-bit key value 
		 * into final set of 48-bit subkeys.
		 */
		int[] PC2 = { 14, 17, 11, 24, 1, 5,
					  3, 28, 15, 6, 21, 10,
					  23, 19, 12, 4, 26, 8,
					  16, 7, 27, 20, 13, 2,
					  41, 52, 31, 37, 47, 55,
					  30, 40, 51, 45, 33, 48,
					  44, 49, 39, 56, 34, 53,
					  46, 42, 50, 36, 29, 32 };

		long k48Bit = 0;
		long helperBit = 0;
		int index = 47;
			
			while(index >= 0){
			helperBit = cdPairs >>> (56 - PC2[index]);
			helperBit = (helperBit & 1) << (47 -index);
			k48Bit = k48Bit^helperBit;
			index--;
			}
		
		return k48Bit;
	}
	/**
	 * We begin Feistel function by applying this expansion permutation 
	 * to its 32-bit input i.e. half of block and it will help to expand 
	 * it to 48-bit.
	 * @return E2
	 */
	private long E() {
		int[] E = { 32, 1, 2, 3, 4, 5,
					4, 5, 6, 7, 8, 9,
					8, 9, 10, 11, 12, 13,
					12, 13, 14, 15, 16, 17,
					16, 17, 18, 19, 20, 21,
					20, 21, 22, 23, 24, 25,
					24, 25, 26, 27, 28, 29,
					28, 29, 30, 31, 32, 1 };
	
		long E32 = this.Rn;
		int index = 0;
		long E48 = 0;
		long helperBit = 0;
		
		for (int n: E){
			
			helperBit = E32 >>> (n-1);
			helperBit = (helperBit & 1)<< index;
			E48 = E48^helperBit;
			index++;
		}
		return E48;

	}
	private long s_func(long in) {
		long out = 0, inBit=0, r, c;
		int sIndex = 7;
		
		while (sIndex >= 0){
			
			inBit = (in >>> sIndex*6) & 0x3FL;
			out = out << 4;
			c = (inBit >>> 1) & 0xFL;
			r = (inBit & 1) ^ ((inBit >>> 4) & 2);
			out = out ^ sBoxes [7-sIndex][(int) (r * 16 + c)];
			sIndex--;
		}
	
		/*
		 * Feistel function concludes by applying this 32 bit permutation to the result
		 * of S-box substitution, it helps to spread output bits across 6 different S-boxes 
		 * in next round.
		 */
		 
		int[] P = { 16, 7, 20, 21,
					29, 12, 28, 17,
					1, 15, 23, 26,
					5, 18, 31, 10,
					2, 8, 24, 14,
					32, 27, 3, 9,
					19, 13, 30, 6,
					22, 11, 4, 25 };
		
		long helperBit = 0;
		int index = 31;
		long afterPermutation = 0;
		
		
		while (index >= 0){
			helperBit = out >>> (32-P[index]);
			helperBit = (helperBit & 1) << (31 -index);
			afterPermutation = afterPermutation ^ helperBit;
			index--;
		}
		
		out = afterPermutation;
		return out;
	}
	

	/**
	 * It's used for final permutation. The final result is permuted by this permutation.
	 */
	private void FP() {
		int[] FP = { 40, 8, 48, 16, 56, 24, 64, 32,
					 39, 7, 47, 15, 55, 23, 63, 31,
					 38, 6, 46, 14, 54, 22, 62, 30,
					 37, 5, 45, 13, 53, 21, 61, 29,
					 36, 4, 44, 12, 52, 20, 60, 28,
					 35, 3, 43, 11, 51, 19, 59, 27,
					 34, 2, 42, 10, 50, 18, 58, 26,
					 33, 1, 41, 9, 49, 17, 57, 25 };
		
		int index = 63;
		long in = 0;
		long helperBit = 0;
		long cdata = this.data;
		
		while (index >= 0){
			helperBit = cdata >>> (64- FP[index]);
			helperBit = (helperBit & 1) << (63 - index);
			in = in ^ helperBit;
			index--;
		}
		
		data = in;
	}
	
	/**
	 * Encryption function using 64-bit block and key.
	 * @param key
	 * @param block
	 * @return data which is encrypted.
	 */

	public long encrypt(long key, long block) {
		
		this.key = key;
		this.data = block;
		IP();
		leftRightHalves();
		to56Bit();
		long k48Bit = 0, in = 0, out = 0, L, R = 0;	
		for (int r : rotations){
			R = E();
			k48Bit = createSubkeys(r);
			in = R ^ k48Bit;
			out = s_func(in);
			L = this.Ln;
			this.Ln = Rn;
			Rn = (out ^ L);
		}
		data = ((Rn << 32) ^ Ln);
		FP();
		return data;
	}
	
	/**
	 * Decryption function.
	 * @param key
	 * @param block
	 * @return data which is decrypted.
	 */

	public long decrypt(long key, long block) {
		this.key = key; this.data = block;
		IP();
		leftRightHalves();
		to56Bit();
		long[] k48Bit = new long[16];
		long in = 0, out = 0, L, R = 0;
		int index =0;
		for (int r : rotations){
			k48Bit[index] = createSubkeys(r);
			index++;
		}
		
		int index2 = 15;
		while ( index2 >= 0){
			R = E();
			in = R ^ k48Bit[index2];
			out = s_func(in);
			L = this.Ln;
			this.Ln = Rn;
			Rn = (out ^ L);
			index2--;
		}
		data = (Rn << 32) ^ Ln;
		FP();
		return data;
	}
	
	/*public static void main(String[] args) {
		
		DES des = new DES(args[0]);
		
		long encrypted = des.encrypt(0x85bc7c34eb750ec5L, 0x0ed9e287fd025012L);
		
		System.out.printf("Ciphertext after Encryption =  %02x      KEY used =  %02x", encrypted, des.key);
	
		long decrypted = des.decrypt(0x85bc7c34eb750ec5L, encrypted);
		
		System.out.println();
		System.out.printf("Original Plaintext         =  %02x  ", des.data);
		System.out.println();
		System.out.printf("Plaintext After Decryption =  %02x", decrypted);
		
		
		
	}
*/
}
