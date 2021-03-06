package SecureIMCard;

import javacard.framework.*;
import javacard.security.*;
import javacardx.crypto.Cipher;

/**
 *
 */
public class SecureIMCard extends Applet
{
    /*SELECT the APDU:                    00 A4 04 00 0A A0 40 41 42 43 44 45 46 10 01 00
    * Gen the ECC keypair:                80 41 01 00 00 -> 90 00
    * Gen the secret:                     80 50 00 00 00 -> B7 78 66 03 0E 65 5F 06 A0 74 17 CA DB C0 38 90 E7 6E 53 B4 [90 00] (20 byte hex secret)
    * Pad to create DES key:              80 51 00 00 00 -> B7 78 66 03 0E 65 5F 06 A0 74 17 CA DB C0 38 90 E7 6E 53 B4 00 00 00 00 [90 00] (Above but with 4 bytes of 00 padding)
    * Do DES Cipher (encryption):         80 70 00 00 08 68 65 6C 6C 6F 62 6F 62 00 -> 48 6F 9F 44 40 FC ED 44 [90 00] ("hellobob encrypted")
    * Do DES Cipher (decryption):         80 70 01 00 08 48 6F 9F 44 40 FC ED 44 00 -> 68 65 6C 6C 6F 62 6F 62 [90 00] ("hellobob decrypted")
     * */

	private static final byte INS_ECC_GEN_KEYPAIR    = (byte) 0x41;
	private static final byte INS_ECC_GENA           = (byte) 0x42;
	private static final byte INS_ECC_GENP           = (byte) 0x43;
	private static final byte INS_ECC_GET_S          = (byte) 0x44;
	private static final byte INS_ECC_GET_W          = (byte) 0x45;
	private static final byte INS_ECC_SET_S          = (byte) 0x46;
	private static final byte INS_ECC_SET_GUEST_W    = (byte) 0x47;
	private static final byte INS_ECC_SIGN           = (byte) 0x48;
	private static final byte INS_ECC_VERIFY         = (byte) 0x49;
	private static final byte INS_ECC_GEN_SECRET     = (byte) 0x50;
	private static final byte INS_ECC_GEN_3DES_KEY   = (byte) 0x51;
	private static final byte INS_ECC_SET_INPUT_TEXT = (byte) 0x59;
	private static final byte INS_ECC_DO_DES_CIPHER  = (byte) 0x70;

	private static final short SW_CRYPTO_UNINITIALIZED_KEY = (short) 0x6B81;
	private static final short SW_CRYPTO_INVALID_INIT      = (short) 0x6B82;
	private static final short SW_CRYPTO_ILLEGAL_USE       = (short) 0x6B83;
	private static final short SW_CRYPTO_ILLEGAL_VALUE     = (short) 0x6B84;
	private static final short SW_CRYPTO_NO_SUCH_ALGORITHM = (short) 0x6B85;

	private static final short SW_APDU_ILLEGAL_USE       = (short) 0x6C81;
	private static final short SW_APDU_IO_ERROR          = (short) 0x6C82;
	private static final short SW_APDU_BAD_LENGTH        = (short) 0x6C83;
	private static final short SW_APDU_T1_IFD_ABORT      = (short) 0x6C84;
	private static final short SW_APDU_NO_T0_GETRESPONSE = (short) 0x6C85;
	private static final short SW_APDU_NO_T0_REISSUE     = (short) 0x6C86;
	private static final short SW_APDU_BUFFER_BOUNDS     = (short) 0x6C87;

	private static final short SW_NEGATIVE_ARRAY   = (short) 0x6D80;
	private static final short SW_SYSTEM_EXCEPTION = (short) 0x6D80;

	private static final short SW_ARRAY_INDEX_OOB = (short) 0x6B91;
	private static final short SW_NULL_POINTER    = (short) 0x6D80;

	private static final short SW_UNKNOWN_CRYPTO_EXCEPTION = (short) 0x6E80;
	private static final short SW_UNKNOWN_APDU_EXCEPTION   = (short) 0x6E81;

	private static final short SW_TRANSACTION_EXCEPTION = (short) 0x6F80;

	private static final short SW_SECURITY_EXCEPTION = (short) 0x6E80;
	private static final short SW_INSTALL_FAILED     = (short) 0x6F81;
	private static final short SW_ILLEGAL_VALUE      = (short) 0x6F82;
	private static final short SW_ILLEGAL_AID        = (short) 0x6F83;

	private static final short FLAGS_SIZE = (short) 5;
	private byte[] output;
	private byte[] inputText;
	private byte[] tempBuffer;
	private byte[] flags;
	private short eccKeyLen = (short) 0;
	private Signature    ecdsa;
	private KeyAgreement ecdhc;
	private KeyPair eccKey = null;
	//	private byte[] guestPublicKey;

	private byte[] secret;

	private Cipher desEcbCipher;
	private byte   desKeyLen;
	private DESKey desKey;
	private byte[] desKeyData;

	private KeyPair testEccKey = null;
	private boolean test;
	private short   inputTextLength;
	private byte[] otherPublicKeyArray;


	public SecureIMCard()
	{

		try
		{
			//Create a transient byte array to store the temporary data
			tempBuffer = JCSystem.makeTransientByteArray((short) 256, JCSystem.CLEAR_ON_DESELECT);
			inputText = JCSystem.makeTransientByteArray((short) 256, JCSystem.CLEAR_ON_DESELECT);
			flags = JCSystem.makeTransientByteArray(FLAGS_SIZE, JCSystem.CLEAR_ON_DESELECT);
			secret = JCSystem.makeTransientByteArray((short) 24, JCSystem.CLEAR_ON_DESELECT);
			output = JCSystem.makeTransientByteArray((short) 512, JCSystem.CLEAR_ON_DESELECT);
			otherPublicKeyArray = JCSystem.makeTransientByteArray((short) 49, JCSystem.CLEAR_ON_DESELECT);

			//Create a ECC(ALG_ECDSA_SHA) object instance
			ecdsa = Signature.getInstance(Signature.ALG_ECDSA_SHA, false);
			ecdhc = KeyAgreement.getInstance(KeyAgreement.ALG_EC_SVDP_DH, false);

			desEcbCipher = Cipher.getInstance(Cipher.ALG_DES_ECB_ISO9797_M2, false);

			// test = false;

			JCSystem.requestObjectDeletion();
		}
		catch (NegativeArraySizeException e)
		{
			ISOException.throwIt(SW_NEGATIVE_ARRAY);
		}
		catch (SystemException e)
		{
			ISOException.throwIt(SW_SYSTEM_EXCEPTION);
		}
		catch (CryptoException e)
		{
			HandleCryptoException(e);
		}

	}


	private void HandleCryptoException(final CryptoException e)
	{
		switch (e.getReason())
		{
			case CryptoException.UNINITIALIZED_KEY:
				ISOException.throwIt(SW_CRYPTO_UNINITIALIZED_KEY);
				break;
			case CryptoException.INVALID_INIT:
				ISOException.throwIt(SW_CRYPTO_INVALID_INIT);
				break;
			case CryptoException.ILLEGAL_USE:
				ISOException.throwIt(SW_CRYPTO_ILLEGAL_USE);
				break;
			case CryptoException.ILLEGAL_VALUE:
				ISOException.throwIt(SW_CRYPTO_ILLEGAL_VALUE);
				break;
			case CryptoException.NO_SUCH_ALGORITHM:
				ISOException.throwIt(SW_CRYPTO_NO_SUCH_ALGORITHM);
				break;
			default:
				ISOException.throwIt(SW_UNKNOWN_CRYPTO_EXCEPTION);
				break;
		}
	}


	public static void install(byte[] bArray, short bOffset, byte bLength)
	{
		try
		{
			new SecureIMCard().register(bArray, (short) (bOffset + 1), bArray[bOffset]);
		}
		catch (ISOException e)
		{
			ISOException.throwIt(SW_INSTALL_FAILED);
		}
		catch (SystemException e)
		{
			HandleSystemException(e);
		}
	}


	private static void HandleSystemException(final SystemException e)
	{
		if (e.getReason() == SystemException.ILLEGAL_VALUE)
		{
			ISOException.throwIt(SW_ILLEGAL_VALUE);

		}
		else if (e.getReason() == SystemException.ILLEGAL_AID)
		{
			ISOException.throwIt(SW_ILLEGAL_AID);

		}
	}


	public void process(APDU apdu)
	{
		try
		{
			if (selectingApplet())
			{
				return;
			}

			byte[] buf = apdu.getBuffer();
			byte apduState = apdu.getCurrentState();
			switch (buf[ISO7816.OFFSET_INS])
			{
				case INS_ECC_GEN_KEYPAIR:
					// GEN_KEYPAIR
					GenEccKeyPair(apdu);
					break;
				case INS_ECC_GENA:
					// ECC_GENA
					getEccKeyA(apdu);
					break;
				case INS_ECC_GENP:
					// ECC_GENP
					getEccKeyP(apdu);
					break;
				case INS_ECC_GET_S:
					// ECC_GENS
					getEccKeyS(apdu);
					break;
				case INS_ECC_GET_W:
					// ECC_GENW
					getEccKeyW(apdu);
					break;
				case INS_ECC_SET_S: //PrivateKey
					// ECC_SETS
					setEccKeyS(apdu);
					break;
				case INS_ECC_SET_GUEST_W: //PublicKey
					// ECC_SETW
					setGuestEccKeyW(apdu);
					break;
				case INS_ECC_SIGN:
					// ECC_SIGN
					Ecc_Sign(apdu);
					break;
				case INS_ECC_VERIFY:
					//ECC_VERIFY
					Ecc_Verify(apdu);
				case INS_ECC_GEN_SECRET:
					Ecc_Gen_Secret(apdu);
					break;
				case INS_ECC_GEN_3DES_KEY:
					gen3DESKeyFromSecret(apdu, secret, (short) secret.length, (short) 24);
					break;
				case INS_ECC_SET_INPUT_TEXT:
					setInputText(apdu);
					break;
				case INS_ECC_DO_DES_CIPHER:
					doDesCipher(apdu);
					break;
				default:
					ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
			}
		}
		catch (APDUException e)
		{
			HandleAPDUException(e);
		}
	}


	private byte[] padSecret(byte[] unpaddedSecret, short secretSize, short keySize)
	{
		short amountToPad = (short) (keySize - secretSize);
		for (short i = 0; i < amountToPad; i++)
		{
			unpaddedSecret[(short) (secretSize + i)] = (byte) 0xFF;
		}
		return unpaddedSecret;
	}


	private void gen3DESKeyFromSecret(final APDU apdu, byte[] secret, short secretSize, short keySize)
	{
		try
		{
			byte apduState = apdu.getCurrentState();

			byte[] buffer = apdu.getBuffer();

			desKey = (DESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_DES_TRANSIENT_RESET, KeyBuilder.LENGTH_DES3_3KEY, false);
			desKeyData = padSecret(secret, secretSize, keySize);
			desKey.setKey(desKeyData, (short) 0);

			desKeyLen = desKey.getKey(buffer, (short) 0);
			//				Util.arrayCopyNonAtomic(publicKey, (short) 0, buffer, (short) 0, publicKeyLength);
			//				Util.arrayCopyNonAtomic(privateKeyByte, (short) 0, buffer, (short) 0, privateKeyLength);

            /*apdu.setOutgoingAndSend((short) 0, desKeyLen);*/

			sendAPDU(apdu, buffer, (short) 0, desKeyLen);

			apduState = apdu.getCurrentState();

		}
		catch (CryptoException e)
		{
			HandleCryptoException(e);
		}
		catch (APDUException e)
		{
			HandleAPDUException(e);
		}

		//		return desKey;
	}


	//Get the key that set into the 'desKey' in setDesKey() function, and return the DESKey object.
	//The plain text length of input key data is 8 bytes for DES, 16 bytes for 2-key triple DES and 24 bytes for 3-key triple DES.
	private Key getDesKey()
	{
		try
		{
			Key tempDesKey = null;
			switch (desKeyLen)
			{
				case (byte) 24:
					tempDesKey = desKey;
					break;
				default:
					ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
					break;
			}
			//Set the 'desKey' key data value into the internal representation
			((DESKey) tempDesKey).setKey(desKeyData, (short) 0);
			return tempDesKey;
		}
		catch (CryptoException e)
		{
			HandleCryptoException(e);
		}
		catch (NullPointerException e)
		{
			ISOException.throwIt(SW_NULL_POINTER);

		}
		catch (ArrayIndexOutOfBoundsException e)
		{
			ISOException.throwIt(SW_ARRAY_INDEX_OOB);
		}
		return null;
	}


	private void setInputText(final APDU apdu)
	{
		byte apduState = apdu.getCurrentState();

		byte[] buffer = apdu.getBuffer();
		short len = apdu.setIncomingAndReceive();

		Util.arrayCopyNonAtomic(buffer, ISO7816.OFFSET_CDATA, inputText, (short) 0, len);
		inputTextLength = len;
	}


	private void sendAPDU(final APDU apdu, byte[] data, short offset, short length)
	{

		try
		{
			byte apduState = apdu.getCurrentState();

			apdu.setOutgoing();                                   // set transmission to outgoing data
			apdu.setOutgoingLength((short) length);                    // set the number of bytes to send to the IFD
			apdu.sendBytesLong(data, (short) offset, (short) length); // send the requested number of bytes to the IFD

			apduState = apdu.getCurrentState();

		}
		catch (APDUException e)
		{
			HandleAPDUException(e);
		}
		catch (SecurityException e)
		{
			ISOException.throwIt(SW_SECURITY_EXCEPTION);
		}
	}


	private void doDesCipher(final APDU apdu)
	{
		try
		{
			//            byte[] buffer = apdu.getBuffer();
			//            short len = apdu.setIncomingAndReceive();
			//
			//            byte mode = buffer[ISO7816.OFFSET_P1] == (byte) 0x00 ? Cipher.MODE_ENCRYPT : Cipher.MODE_DECRYPT;
			//            Cipher cipher = desEcbCipher;
			//
			//            Key key = getDesKey();
			//
			//            cipher.init(key, mode);
			//
			//            cipher.doFinal(buffer, ISO7816.OFFSET_CDATA, len, buffer, (short) 0);
			//            apdu.setOutgoingAndSend((short) 0, len);

			byte apduState = apdu.getCurrentState();

			byte[] buffer = apdu.getBuffer();

			Util.arrayFillNonAtomic(output, (short) 0, (short) output.length, (byte) 0);

			byte mode = buffer[ISO7816.OFFSET_P1] == (byte) 0x00 ? Cipher.MODE_ENCRYPT : Cipher.MODE_DECRYPT;
			Cipher cipher = desEcbCipher;

			Key key = getDesKey();

			cipher.init(key, mode);

			short encryptedLength = cipher.doFinal(inputText, (short) 0, inputTextLength, output, (short) 0);
			//            apdu.setOutgoingAndSend((short) 0, inputTextLength);

			//            sendAPDU(apdu, output, (short) 0, encryptedLength);

			apdu.setOutgoing();

			apdu.setOutgoingLength(encryptedLength);

			apdu.sendBytesLong(output, (short) 0, encryptedLength);

			apduState = apdu.getCurrentState();

		}
		catch (CryptoException e)
		{
			HandleCryptoException(e);
		}
		catch (APDUException e)
		{
			HandleAPDUException(e);
		}
	}


	private void Ecc_Gen_Secret(final APDU apdu)
	{
		try
		{
			byte apduState = apdu.getCurrentState();

			byte[] buffer = apdu.getBuffer();

			Util.arrayFillNonAtomic(otherPublicKeyArray, (short) 0, (short) otherPublicKeyArray.length, (byte) 0);

			testEccKey.genKeyPair();
			short otherPublicKeyLength = Util.getShort(tempBuffer, (short) 128);
			// Sets the point of the curve comprising the public key.
			((ECPublicKey) testEccKey.getPublic()).setW(tempBuffer, (short) 130, otherPublicKeyLength);
			//            if (test)
			//            {
			//                publicKeyLength = ((ECPublicKey) (testEccKey.getPublic())).getW(publicKey, (short) 0);
			//            }
			//            else
			//            {
			//                Util.arrayCopyNonAtomic(buffer, ISO7816.OFFSET_CDATA, publicKey, (short) 0, len);
			//                publicKeyLength = (short) len;
			//            }

			//            short publicKeyLength = ((ECPublicKey) (eccKey.getPublic())).getW(publicKey, (short) 0);
			ECPrivateKey privateKey = (ECPrivateKey) eccKey.getPrivate();
			ecdhc.init(privateKey);
			//            byte[] privateKeyArray = new byte[24];
			//            short privateKeyLength = privateKey.getS(privateKeyArray, (short) 0);

			PublicKey otherPublicKey = testEccKey.getPublic();
			otherPublicKeyLength = ((ECPublicKey) otherPublicKey).getW(otherPublicKeyArray, (short) 0);

			short secretSize = ecdhc.generateSecret(otherPublicKeyArray, (short) 0, otherPublicKeyLength, secret, (short) 0);
			Util.arrayCopyNonAtomic(secret, (short) 0, buffer, (short) 0, (short) eccKeyLen);
			//				Util.arrayCopyNonAtomic(publicKey, (short) 0, buffer, (short) 0, publicKeyLength);
			//				Util.arrayCopyNonAtomic(privateKeyByte, (short) 0, buffer, (short) 0, privateKeyLength);
	        /*apdu.setOutgoingAndSend((short) 0, (short) eccKeyLen);*/

			sendAPDU(apdu, buffer, (short) 0, eccKeyLen);

			apduState = apdu.getCurrentState();

			//			apdu.setOutgoingAndSend((short) 0, publicKeyLength);
			//			apdu.setOutgoingAndSend((short) 0, privateKeyLength);
		}
		catch (CryptoException e)
		{
			HandleCryptoException(e);
		}
		catch (APDUException e)
		{
			HandleAPDUException(e);
		}
		catch (ArrayIndexOutOfBoundsException e)
		{
			ISOException.throwIt(SW_ARRAY_INDEX_OOB);
		}
		catch (NullPointerException e)
		{
			ISOException.throwIt(SW_NULL_POINTER);
		}
	}


	//According to the different key length specified in the incoming APDU , generate ECC key pair and store in the  global variable 'eccKey'
	private void GenEccKeyPair(APDU apdu)
	{
		try
		{
			byte apduState = apdu.getCurrentState();

			byte[] buffer = apdu.getBuffer();
			short keyLen = (short) 0;
			switch (buffer[ISO7816.OFFSET_P1])
			{
				case (byte) 0x01: // 192
					//Constructs a KeyPair instance for the specified algorithm and keylength;
					eccKey = new KeyPair(KeyPair.ALG_EC_FP, KeyBuilder.LENGTH_EC_FP_192);
					keyLen = (short) 24;

					testEccKey = new KeyPair(KeyPair.ALG_EC_FP, KeyBuilder.LENGTH_EC_FP_192);

					break;
				default:
					eccKey = new KeyPair(KeyPair.ALG_EC_FP, KeyBuilder.LENGTH_EC_FP_192);
					keyLen = (short) 24;

					testEccKey = new KeyPair(KeyPair.ALG_EC_FP, KeyBuilder.LENGTH_EC_FP_192);
					break;
			}
			//(Re)Initializes the key objects encapsulated in this 'eccKey' KeyPair instance with new key values.
			eccKey.genKeyPair();

			testEccKey.genKeyPair();

			eccKeyLen = keyLen;

			apduState = apdu.getCurrentState();

		}
		catch (CryptoException e)
		{
			HandleCryptoException(e);
		}
	}


	//Returns the first coefficient 'A' of the curve of the key.
	private void getEccKeyA(APDU apdu)
	{
		byte[] buffer = apdu.getBuffer();
		((ECPrivateKey) eccKey.getPrivate()).getA(buffer, (short) 0);
		apdu.setOutgoingAndSend((short) 0, eccKeyLen);
	}


	//Returns the field specification parameter value of the key.
	private void getEccKeyP(APDU apdu)
	{
		byte[] buffer = apdu.getBuffer();
		((ECPrivateKey) eccKey.getPrivate()).getField(buffer, (short) 0);
		apdu.setOutgoingAndSend((short) 0, eccKeyLen);
	}


	//Returns the coefficient 'S' of the curve of the key.
	private void getEccKeyS(APDU apdu)
	{
		try
		{
			byte[] buffer = apdu.getBuffer();
			short length = ((ECPrivateKey) eccKey.getPrivate()).getS(buffer, (short) 0);


            /*apdu.setOutgoingAndSend((short) 0, length);*/

			sendAPDU(apdu, buffer, (short) 0, length);
		}
		catch (CryptoException e)
		{
			HandleCryptoException(e);
		}
		catch (APDUException e)
		{
			HandleAPDUException(e);
		}
	}


	//Returns the coefficient 'W' of the curve of the key.
	private void getEccKeyW(APDU apdu)
	{
		try
		{
			byte[] buffer = apdu.getBuffer();
			short length = ((ECPublicKey) eccKey.getPublic()).getW(buffer, (short) 0);


            /*apdu.setOutgoingAndSend((short) 0, length);*/

			sendAPDU(apdu, buffer, (short) 0, length);
		}
		catch (CryptoException e)
		{
			HandleCryptoException(e);
		}
		catch (APDUException e)
		{
			HandleAPDUException(e);
		}
	}


	//Set the value of ECC private key(SetS)
	private void setEccKeyS(APDU apdu)
	{
		byte[] buffer = apdu.getBuffer();
		short len = apdu.setIncomingAndReceive();
		switch (buffer[ISO7816.OFFSET_P1])
		{
			case (byte) 0x01: // 192 key
				if (len != 24)
				{
					ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
				}
				eccKeyLen = 24;
				//Constructs a KeyPai instance for the ALG_EC_FP algorithm and keylength is 192;
				eccKey = new KeyPair(KeyPair.ALG_EC_FP, KeyBuilder.LENGTH_EC_FP_192);
				break;
			//			case (byte) 0x02:
			//				if (len != 32)
			//				{
			//					ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
			//				}
			//				eccKeyLen = 32;
			//				//Constructs a KeyPai instance for the ALG_EC_FP algorithm and keylength is 256;
			//				//Here, the KeyBuilder.LENGTH_EC_FP_256 only be used in JavaCard API 3.0.4
			//				eccKey = new KeyPair(KeyPair.ALG_EC_FP, KeyBuilder.LENGTH_EC_FP_256);
			//				break;
			//			case (byte) 0x03: // 384 key
			//				if (len != 48)
			//				{
			//					ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
			//				}
			//				eccKeyLen = 48;
			//				//Constructs a KeyPai instance for the ALG_EC_FP algorithm and keylength is 384;
			//				//Here, the KeyBuilder.LENGTH_EC_FP_384 only be used in JavaCard API 3.0.4
			//				eccKey = new KeyPair(KeyPair.ALG_EC_FP, KeyBuilder.LENGTH_EC_FP_384);
			//				break;
			default:
				//				ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
				if (len != 24)
				{
					ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
				}
				eccKeyLen = 24;
				//Constructs a KeyPai instance for the ALG_EC_FP algorithm and keylength is 192;
				eccKey = new KeyPair(KeyPair.ALG_EC_FP, KeyBuilder.LENGTH_EC_FP_192);
				break;
		}
		//In tempBuffer, the offset from 0 to 1 positions stored ECC private key, including 0 to 0 store the private key length, 130 to 255 store the private key data
		Util.setShort(tempBuffer, (short) 0, len);
		Util.arrayCopyNonAtomic(buffer, ISO7816.OFFSET_CDATA, tempBuffer, (short) 2, len);
	}


	//Set the value of ECC public key(SetW)
	private void setEccKeyW(APDU apdu, short len)
	{
		byte[] buffer = apdu.getBuffer();
		switch (buffer[ISO7816.OFFSET_P1])
		{
			case (byte) 0x01: // 192 key
				if (len != 24 * 2 + 1)
				{
					ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
				}
				eccKeyLen = 24;
				//Constructs a KeyPair instance for the ALG_EC_FP algorithm and keylength is 192;
				eccKey = new KeyPair(KeyPair.ALG_EC_FP, KeyBuilder.LENGTH_EC_FP_192);
				break;
			default:
				if (len != 24 * 2 + 1)
				{
					ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
				}
				eccKeyLen = 24;
				//Constructs a KeyPair instance for the ALG_EC_FP algorithm and keylength is 192;
				eccKey = new KeyPair(KeyPair.ALG_EC_FP, KeyBuilder.LENGTH_EC_FP_192);
				//				ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
				break;
		}
		//In tempBuffer, the offset from 128 to 255 positions stored ECC public key, including 128 to 129 store the public key length, 130 to 255 store the private key data
		Util.setShort(tempBuffer, (short) 128, len);
		Util.arrayCopyNonAtomic(buffer, ISO7816.OFFSET_CDATA, tempBuffer, (short) 130, len);
	}


	//Set the value of ECC public key(SetW)
	private void setGuestEccKeyW(APDU apdu)
	{
		try
		{
			byte[] buffer = apdu.getBuffer();
			short len = apdu.setIncomingAndReceive();
			switch (buffer[ISO7816.OFFSET_P1])
			{
				case (byte) 0x01: // 192 key
					if (len != 24 * 2 + 1)
					{
						ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
					}
					eccKeyLen = 24;
					//Constructs a KeyPair instance for the ALG_EC_FP algorithm and keylength is 192;
					testEccKey = new KeyPair(KeyPair.ALG_EC_FP, KeyBuilder.LENGTH_EC_FP_192);
					break;
				default:
					if (len != 24 * 2 + 1)
					{
						ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
					}
					eccKeyLen = 24;
					//Constructs a KeyPair instance for the ALG_EC_FP algorithm and keylength is 192;
					testEccKey = new KeyPair(KeyPair.ALG_EC_FP, KeyBuilder.LENGTH_EC_FP_192);
					//				ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
					break;
			}
			//In tempBuffer, the offset from 128 to 255 positions stored ECC public key, including 128 to 129 store the public key length, 130 to 255 store the private key data
			Util.setShort(tempBuffer, (short) 128, len);
			Util.arrayCopyNonAtomic(buffer, ISO7816.OFFSET_CDATA, tempBuffer, (short) 130, len);
		}
		catch (CryptoException e)
		{
			HandleCryptoException(e);
		}
		catch (TransactionException e)
		{
			ISOException.throwIt(SW_TRANSACTION_EXCEPTION);
		}
		catch (NullPointerException e)
		{
			ISOException.throwIt(SW_NULL_POINTER);
		}
		catch (ArrayIndexOutOfBoundsException e)
		{
			ISOException.throwIt(SW_ARRAY_INDEX_OOB);
		}
	}


	//ECC signature
	private void Ecc_Sign(APDU apdu)
	{
		try
		{
			byte[] buffer = apdu.getBuffer();
			short len = apdu.setIncomingAndReceive();

			//(Re)Initializes the key objects encapsulated in this KeyPair instance with new key values.
			eccKey.genKeyPair();
			short eccPriKeyLen = Util.getShort(tempBuffer, (short) 0);
			//Returns a reference to the private key component of this  ECC KeyPair object.
			((ECPrivateKey) eccKey.getPrivate()).setS(tempBuffer, (short) 2, eccPriKeyLen);
			//Initializes the Signature object with the ecdsa Key
			ecdsa.init(eccKey.getPrivate(), Signature.MODE_SIGN);
			//Generates the signature of all input data.
			short lenTmp = ecdsa.sign(buffer, ISO7816.OFFSET_CDATA, len, buffer, (short) 0);

			apdu.setOutgoingAndSend((short) 0, lenTmp);
		}
		catch (CryptoException e)
		{
			HandleCryptoException(e);
		}
		catch (APDUException e)
		{
			HandleAPDUException(e);
		}
	}


	//Verify the ECC signature, the format of APDU data field is : the signature data and the data to be verified
	private void Ecc_Verify(APDU apdu)
	{
		try
		{
			byte[] buffer = apdu.getBuffer();
			short len = apdu.setIncomingAndReceive();

			short signLen = buffer[ISO7816.OFFSET_P1];
			//(Re)Initializes the key objects encapsulated in 'eccKey' KeyPair instance with new key values.
			eccKey.genKeyPair();
			short eccPubKeyLen = Util.getShort(tempBuffer, (short) 128);
			// Sets the point of the curve comprising the public key.
			((ECPublicKey) eccKey.getPublic()).setW(tempBuffer, (short) 130, eccPubKeyLen);
			short plainLen = (short) (len - signLen);
			short tmpOff = (short) (ISO7816.OFFSET_CDATA + signLen);
			//Initializes the Signature object with the appropriate Key
			ecdsa.init(eccKey.getPublic(), Signature.MODE_VERIFY);
			//Verify the signature of input data against the passed in ECC signature.
			boolean ret = ecdsa.verify(buffer, (short) tmpOff, plainLen, buffer, ISO7816.OFFSET_CDATA, signLen);
			buffer[(short) 0] = ret ? (byte) 1 : (byte) 0;
			apdu.setOutgoingAndSend((short) 0, (short) 1);
		}
		catch (CryptoException e)
		{
			HandleCryptoException(e);
		}
		catch (APDUException e)
		{
			HandleAPDUException(e);
		}
	}


	private void HandleAPDUException(final APDUException e)
	{
		switch (e.getReason())
		{
			case APDUException.ILLEGAL_USE:
				ISOException.throwIt(SW_APDU_ILLEGAL_USE);
				break;
			case APDUException.IO_ERROR:
				ISOException.throwIt(SW_APDU_IO_ERROR);
				break;
			case APDUException.BAD_LENGTH:
				ISOException.throwIt(SW_APDU_BAD_LENGTH);
				break;
			case APDUException.T1_IFD_ABORT:
				ISOException.throwIt(SW_APDU_T1_IFD_ABORT);
				break;
			case APDUException.BUFFER_BOUNDS:
				ISOException.throwIt(SW_APDU_BUFFER_BOUNDS);
				break;
			case APDUException.NO_T0_GETRESPONSE:
				ISOException.throwIt(SW_APDU_NO_T0_GETRESPONSE);
				break;
			case APDUException.NO_T0_REISSUE:
				ISOException.throwIt(SW_APDU_NO_T0_REISSUE);
				break;
			default:
				ISOException.throwIt(SW_UNKNOWN_APDU_EXCEPTION);
				break;
		}
	}

}