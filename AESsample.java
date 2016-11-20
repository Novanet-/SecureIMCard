/*
 * @file  AESSample.java
 * @version v1.0
 * Package AID: 4A617661436172644F53
 * Applet AID:  4A617661436172644F5301
 * @brief The ALgorithm of AES Sample Code in JavaCard API Specification
 * @comment The purpose of this example is only used to show the usage of API functions and there is no practical significance.
 * @copyright Copyright(C) 2016 JavaCardOS Technologies Co., Ltd. All rights reserved.
 */
package JavaCardOS.Sample.Algorithm;

import javacard.framework.*;
import javacard.security.KeyBuilder;
import javacard.security.*;
import javacardx.crypto.*;

public class AESSample extends Applet
{
   private static final byte INS_SET_AES_KEY              = (byte)0x10;
    private static final byte INS_SET_AES_ICV              = (byte)0x11;
    private static final byte INS_DO_AES_CIPHER            = (byte)0x12;
       
    private byte aesKeyLen;
    private byte[] aesKey;
    private byte[] aesICV;

    private Cipher aesEcbCipher;
    private Cipher aesCbcCipher;

    private Key tempAesKey1;
    private Key tempAesKey2;
    private Key tempAesKey3;
   
    public AESSample()
    {
        aesKey = new byte[32];
        aesICV = new byte[16];
        aesKeyLen = 0;
        //Create a AES ECB/CBS object instance of the AES algorithm.
        aesEcbCipher = Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_ECB_NOPAD, false);
        aesCbcCipher = Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_CBC_NOPAD, false);
      //Create uninitialized cryptographic keys for AES algorithms
        tempAesKey1 = KeyBuilder.buildKey(KeyBuilder.TYPE_AES_TRANSIENT_DESELECT, KeyBuilder.LENGTH_AES_128, false);
        tempAesKey2 = KeyBuilder.buildKey(KeyBuilder.TYPE_AES_TRANSIENT_DESELECT, KeyBuilder.LENGTH_AES_192, false);
        tempAesKey3 = KeyBuilder.buildKey(KeyBuilder.TYPE_AES_TRANSIENT_DESELECT, KeyBuilder.LENGTH_AES_256, false);

        JCSystem.requestObjectDeletion();
    }
   
   public static void install(byte[] bArray, short bOffset, byte bLength)
   {
      new AESSample().register(bArray, (short) (bOffset + 1), bArray[bOffset]);
   }

   public void process(APDU apdu)
   {
      if (selectingApplet())
      {
         return;
      }

      byte[] buf = apdu.getBuffer();
        short len = apdu.setIncomingAndReceive();
       
      switch (buf[ISO7816.OFFSET_INS])
      {
      case INS_SET_AES_KEY:
           // SET_AES_KEY
            setAesKey(apdu, len);
            break;
        case INS_SET_AES_ICV:
           // SET_AES_ICV
            setAesICV(apdu, len);
            break;
        case INS_DO_AES_CIPHER:
           //DO_AES_CIPHER
            doAesCipher(apdu, len);
            break;
      default:
         ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
      }
   }
   
   //Set the key of AES Encrypt/Decrypt
    private void setAesKey(APDU apdu, short len)
    {
        byte[] buffer = apdu.getBuffer();
        byte keyLen = 0;
        switch (buffer[ISO7816.OFFSET_P1])
        {
        case (byte)0x01:
            if (len != 16) // The length of key is 16 bytes
            {
                ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
            }
            keyLen = (byte)16;
            break;
        case (byte)0x02:
            if (len != 24) //The length of key is 24 bytes
            {
                ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
            }
            keyLen = (byte)24;
            break;
        case (byte)0x03:
            if (len != 32) //The length of key is 32 bytes
            {
                ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
            }
            keyLen = (byte)32;
            break;
        default:
            ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
            break;
        }

        JCSystem.beginTransaction();
        //Copy the incoming AES Key value to the global variable 'aesKey'
        Util.arrayCopy(buffer, ISO7816.OFFSET_CDATA, aesKey, (short)0, len);
        aesKeyLen = keyLen;
        JCSystem.commitTransaction();
    }

   //Set AES ICV, ICV is the initial vector
    private void setAesICV(APDU apdu, short len)
    {
        if (len != 16)
        {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        //Copy the incoming ICV value to the global variable 'aesICV'
        Util.arrayCopy(apdu.getBuffer(), ISO7816.OFFSET_CDATA, aesICV, (short)0, (short)16);
    }

   //Sets the Key data, and return the AESKey object. The plaintext length of input key data is 16/24/32 bytes.
    private Key getAesKey()
    {
        Key tempAesKey = null;
        switch (aesKeyLen)
        {
        case (byte)16:
            tempAesKey = tempAesKey1;
            break;
        case (byte)24:
            tempAesKey = tempAesKey2;
            break;
        case (byte)32:
            tempAesKey = tempAesKey3;
            break;
        default:
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
            break;
        }
      //Set the 'aesKey' key data value into the internal representation
        ((AESKey)tempAesKey).setKey(aesKey, (short)0);
        return tempAesKey;
    }
   
   //AES algorithm encrypt and decrypt
    private void doAesCipher(APDU apdu, short len)
    {
       //The byte length to be encrypted/decrypted must be a multiple of 16
        if (len <= 0 || len % 16 != 0)
        {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }

        byte[] buffer = apdu.getBuffer();
        Key key = getAesKey();
        byte mode = buffer[ISO7816.OFFSET_P1] == (byte)0x00 ? Cipher.MODE_ENCRYPT : Cipher.MODE_DECRYPT;
        Cipher cipher = buffer[ISO7816.OFFSET_P2] == (byte)0x00 ? aesEcbCipher : aesCbcCipher;
        //Initializes the 'cipher' object with the appropriate Key and algorithm specific parameters.
        //AES algorithms in CBC mode expect a 16-byte parameter value for the initial vector(IV)
        if (cipher == aesCbcCipher)
        {
            cipher.init(key, mode, aesICV, (short)0, (short)16);
        }
        else
        {
            cipher.init(key, mode);
        }
        //This method must be invoked to complete a cipher operation. Generates encrypted/decrypted output from all/last input data.
        cipher.doFinal(buffer, ISO7816.OFFSET_CDATA, len, buffer, (short)0);
        apdu.setOutgoingAndSend((short)0, len);
    }

}
