/*
 * Herkunft/Origin: http://java-crypto.bplaced.net/
 * Programmierer/Programmer: Michael Fehr
 * Copyright/Copyright: verschiedene Copyrights / different copyrights
 * Lizenttext/Licence: verschiedene Lizenzen / different licences
 * getestet mit/tested with: Java Runtime Environment 11.0.5 x64
 * verwendete IDE/used IDE: intelliJ IDEA 2019.3.1
 * Datum/Date (dd.mm.jjjj): 22.02.2020
 * Funktion: Bitcoin Erzeugung von Schluesseln und Adressen
 * Function: Bitcoin Generate Keys and Addresses
 *
 * Hinweis/Notice
 * Sie benoetigen diese externen Klassen / you need these external classes:
 * TeePrintStream.java https://github.com/oreillymedia/java_cookbook_3e/blob/master/javacooksrc/javacooksrc/main/java/io/TeePrintStream.java
 * Base58NotBitcoinJ https://gist.github.com/vrotaru/1753908
 * Ripe1md160 https://github.com/nayuki/Bitcoin-Cryptography-Library/blob/master/java/io/nayuki/bitcoin/crypto/Ripemd160.java
 */

import java.io.IOException;
import java.security.*;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECPoint;

public class BitcoinGenerateKeysAndAddresses {
    public static void main(String[] args) throws NoSuchProviderException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, IOException {

        boolean testnetwork = true; // for mainnetwork false, for testnetwork true
        TeePrintStream ts = new TeePrintStream(System.out, "Bitcoin manuelle Erzeugung von Schluesseln und Adressen.txt", true);
        System.setOut(ts);

        System.out.println("Bitcoin manuelle Erzeugung von Schluesseln und Adressen");

        // 1 erzeuge ein schlüsselpaar
        System.out.println("\nSchritt 1: Erzeugung eines Schluesselpaares");
        if (testnetwork == true) {
            System.out.println("Erzeugte Schluessel sind fuer das Bitcoin Test Network");
        } else {
            System.out.println("Erzeugte Schluessel sind fuer das Bitcoin Main Network");
        }

        String eccCurvenameString = "secp256k1"; // curve for bitcoin
        KeyPairGenerator keypairGenerator = KeyPairGenerator.getInstance("EC", "SunEC");
        ECGenParameterSpec ecSpec = new ECGenParameterSpec(eccCurvenameString);
        keypairGenerator.initialize(ecSpec, new SecureRandom());
        KeyPair ecKey = keypairGenerator.genKeyPair();
        System.out.println("EC-Keypair:" + ecKey.getPrivate().getAlgorithm());
        System.out.println("EC Private Key:" + "Laenge: " + ecKey.getPrivate().getEncoded().length + " Key:\n" + byteArrayPrint(ecKey.getPrivate().getEncoded(), 32));
        System.out.println("EC Public  Key:" + "Laenge: " + ecKey.getPublic().getEncoded().length + " Key:\n" + byteArrayPrint(ecKey.getPublic().getEncoded(), 32));
        //System.out.println("EC Public  Key:" + printHexBinary(ecKey.getPublic().getEncoded()));
        System.out.println("EC Public  Key:" + ecKey.getPublic().toString());
        PublicKey publicKey = ecKey.getPublic();
        PrivateKey privateKey = ecKey.getPrivate();

        // 2 erzeuge die private key adresse
        System.out.println("Der Private Key in voller Laenge (vollstaendig) und den letzten 32 Byte (gekuerzt)");
        String ecPrivateKeyFullString = bytesToHex(privateKey.getEncoded());
        System.out.println("Private Key vollstaendig:" + ecPrivateKeyFullString);
        String ecPrivateKeyString = ecPrivateKeyFullString.substring(64, 128);
        System.out.println("Private Key gekuerzt    :" + ecPrivateKeyString);

        System.out.println("\nSchritt 2: Umwandlung des Private Keys in das Base58- bzw. WIF-Format");
        System.out.println("Die einzelnen Schritte folgen dem Artikel https://en.bitcoin.it/wiki/Wallet_import_format");

        // testvectors for bitcoin main and testnet
        //
        // https://walletgenerator.net/?currency=Bitcoin#
        // testnet: testnetwork = true
        // String privateKeyAddressWif = generatePrivateKeyAddress(testnetwork, "F93FECB8F617ABE291BE83300DBB2D0EDCB1CBB3F0CB5E502CEAFF6AB5F868F5");
        // result in wif uncompressed format: 93UgusbzSkSUbUk4N9T7eHdU2H7AsqvpoFY9b5FCwcMGmLkdwkH
        //
        // mainnet: testnetwork = false
        // String privateKeyAddressWif = generatePrivateKeyAddress(testnetwork, "0C28FCA386C7A227600B2FE50B7CAE11EC86D3BF1FBE471BE89827E19D72AA1D");
        // result in wif uncompressed format: 5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ
        //
        String privateKeyAddressWif = generatePrivateKeyAddress(testnetwork, ecPrivateKeyString);

        System.out.println("\nZusammenfassung von Schritt 2");
        if (testnetwork == true) {
            System.out.println("Erzeugte Schluessel sind fuer das Bitcoin Test Network");
        } else {
            System.out.println("Erzeugte Schluessel sind fuer das Bitcoin Main Network");
        }
        System.out.println("Private Key im 32 Byte Format: " + ecPrivateKeyString);
        System.out.println("Private Key im WIF-Format    : " + privateKeyAddressWif);

        // https://en.bitcoin.it/wiki/Wallet_import_format
        // http://gobittest.appspot.com/PrivateKey
        // https://bitcoin.stackexchange.com/questions/63949/java-way-to-convert-a-256-bit-private-key-to-wif

        System.out.println("\nSchritt 3: Oeffentliche Adresse des Wallets");
        System.out.println("Die einzelnen Schritte folgen dem Artikel https://www.novixys.com/blog/generate-bitcoin-addresses-java");

        String publicKeyAddressWif = generatePublicKeyAddress(testnetwork, publicKey);
        System.out.println("\nZusammenfassung von Schritt 3");

        if (testnetwork == true) {
            System.out.println("Erzeugte Schluessel sind fuer das Bitcoin Test Network");
        } else {
            System.out.println("Erzeugte Schluessel sind fuer das Bitcoin Main Network");
        }
        System.out.println("Public Key im 32 Byte Format: " + bytesToHex(publicKey.getEncoded()));
        System.out.println("Public Key im WIF-Format    : " + publicKeyAddressWif);

        System.out.println("\n* * * Zusammenfassung aller Schluessel und Adressen * * *");
        if (testnetwork == true) {
            System.out.println("Erzeugte Schluessel sind fuer das Bitcoin Test Network");
        } else {
            System.out.println("Erzeugte Schluessel sind fuer das Bitcoin Main Network");
        }
        System.out.println("EC Private Key im Format    :" + ecPrivateKeyString);
        System.out.println("EC Private Key im WIF-Format:" + privateKeyAddressWif);
        System.out.println("EC Public Key im WIF-Format :" + publicKeyAddressWif);
        System.out.println("\nDie korrekte Umwandlung fuer das Main Network kann ueber diese beiden Services ueberprueft werden:");
        System.out.println("Private Key im WIF-Format         : http://gobittest.appspot.com/PrivateKey");
        System.out.println("Oeffentliche Adresse im WIF-Format: http://gobittest.appspot.com/Address");
        System.out.println("");
        // close TeePrintStream
        ts.close();
    }

    public static String generatePrivateKeyAddress(boolean testnetwork, String privateKeyString) throws NoSuchAlgorithmException {
        // code: https://en.bitcoin.it/wiki/Wallet_import_format
        // 2 - Add a 0x80 byte in front of it for mainnet addresses or 0xef for testnet addresses. Also add a 0x01 byte at the end if the private key will correspond to a compressed public key
        //
        // 800C28FCA386C7A227600B2FE50B7CAE11EC86D3BF1FBE471BE89827E19D72AA1D
        System.out.println("\n2 - Add a 0x80 byte in front of it for mainnet addresses or 0xef for testnet addresses.");
        String step2;
        if (testnetwork == true) {
            step2 = "EF" + privateKeyString;
        } else {
            step2 = "80" + privateKeyString;
        }
        System.out.println("Step 2 Extended Private Key:" + step2);
        // 3 - Perform SHA-256 hash on the extended key
        //
        //   8147786C4D15106333BF278D71DADAF1079EF2D2440A4DDE37D747DED5403592
        System.out.println("\n3 - Perform SHA-256 hash on the extended key");
        byte[] data = hexStringToByteArray(step2);
        byte[] digest = MessageDigest.getInstance("SHA-256").digest(data);
        //byte[] digest = MessageDigest.getInstance("SHA-256").digest(hexStringToByteArray(privateKeyStringStep2));
        String step3 = bytesToHex(digest);
        System.out.println("Step 3 SHA256:" + step3);
        // 4 - Perform SHA-256 hash on result of SHA-256 hash
        //
        //   507A5B8DFED0FC6FE8801743720CEDEC06AA5C6FCA72B07C49964492FB98A714
        System.out.println("\n4 - Perform SHA-256 hash on result of SHA-256 hash");
        byte[] digest2 = MessageDigest.getInstance("SHA-256").digest(digest);
        //byte[] digest2 = MessageDigest.getInstance("SHA-256").digest(hexStringToByteArray(result));
        String step4 = bytesToHex(digest2);
        System.out.println("Step 4 SHA256:" + step4);
        // 5 - Take the first 4 bytes of the second SHA-256 hash, this is the checksum
        //
        //   507A5B8D
        System.out.println("\n5 - Take the first 4 bytes of the second SHA-256 hash, this is the checksum");
        String step5 = step4.substring(0, 8);
        System.out.println("Step 5 First 4 Bytes from Step 4:" + step5);
        // 6 - Add the 4 checksum bytes from point 5 at the end of the extended key from point 2
        //
        //   800C28FCA386C7A227600B2FE50B7CAE11EC86D3BF1FBE471BE89827E19D72AA1D507A5B8D
        System.out.println("\n6 - Add the 4 checksum bytes from point 5 at the end of the extended key from point 2");
        String step6 = step2 + step5;
        System.out.println("Step 6 complete String:" + step6);
        // 7 - Convert the result from a byte string into a base58 string using Base58Check encoding. This is the Wallet Import Format
        // Link: https://en.bitcoin.it/wiki/Base58Check_encoding
        //   5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ
        System.out.println("\n7 - Convert the result from a byte string into a base58 string");
        byte[] step6ByteArray = hexStringToByteArray(step6);
        //String step7String = Base58.encode(step6ByteArray);
        String step7 = Base58NotBitcoinJ.encode(step6ByteArray);
        System.out.println("Step 7 Base58-String:" + step7);
        System.out.println("Step 7 Base58-String:" + "93UgusbzSkSUbUk4N9T7eHdU2H7AsqvpoFY9b5FCwcMGmLkdwkH" + " walletgenerator.net");
        return step7;
    }

    public static String generatePublicKeyAddress(boolean testnetwork, PublicKey publicKey) throws NoSuchAlgorithmException {
        ECPublicKey epub = (ECPublicKey) publicKey;
        // routinen von https://www.novixys.com/blog/generate-bitcoin-addresses-java/
        ECPoint pt = epub.getW();
        String sx = adjustTo64(pt.getAffineX().toString(16)).toUpperCase();
        String sy = adjustTo64(pt.getAffineY().toString(16)).toUpperCase();
        String bcPub = "04" + sx + sy;
        System.out.println("\nbcPub: " + bcPub + " Length:" + bcPub.length());

        MessageDigest sha = MessageDigest.getInstance("SHA-256");
        byte[] s1 = sha.digest(hexStringToByteArray(bcPub));
        System.out.println("\n  sha: " + bytesToHex(s1).toUpperCase());
        // prints sha: 7524DC35AEB4B62A0F1C90425ADC6732A7C5DF51A72E8B90983629A7AEC656A0
        byte[] r1 = Ripemd160.getHash(s1);
        System.out.println("\nr1:" + bytesToHex(r1) + " Length:" + r1.length);

        // mainnet = 0x00, testnet = 111
        //Next we need to add a version byte of 0x00 at the beginning of the hash.
        byte[] r2 = new byte[r1.length + 1];
        if (testnetwork == true) {
            r2[0] = 111; // testnet
        } else {
            r2[0] = 0; // mainnet
        }

        for (int i = 0; i < r1.length; i++) r2[i + 1] = r1[i];
        System.out.println("\n  rmd: " + bytesToHex(r2).toUpperCase());
        // prints rmd: 00C5FAE41AB21FA56CFBAFA3AE7FB5784441D11CEC
        System.out.println("\nexp:   " + "00C5FAE41AB21FA56CFBAFA3AE7FB5784441D11CEC");

        // 6. Repeat the SHA-256 Hashing Twice
        // We now need to perform a SHA-256 hash twice on the result above.
        byte[] s2 = sha.digest(r2);
        System.out.println("\n  sha: " + bytesToHex(s2).toUpperCase());
        byte[] s3 = sha.digest(s2);
        System.out.println("\n  sha: " + bytesToHex(s3).toUpperCase());

        // The first 4 bytes of the result of the second hashing is used as the address checksum. It is appended to the RIPEMD160 hash above. This is the 25-byte bitcoin address.
        byte[] a1 = new byte[25];
        for (int i = 0; i < r2.length; i++) a1[i] = r2[i];
        for (int i = 0; i < 4; i++) a1[21 + i] = s3[i];

        System.out.println("\n25 Byte Bitcoin Address:" + bytesToHex(a1) + " Länge:" + a1.length);

        // 7. Encode the Address Using Base58
        // We now use the Base58.encode() method from the bitcoinj library to arrive at the final bitcoin address.
        //System.out.println("  adr: " + Base58.encode(a1));
        System.out.println("\n  adr: " + Base58NotBitcoinJ.encode(a1));
        // This is the address to which the bitcoin should be sent to in a transaction.
        // test addres with http://gobittest.appspot.com/Address
        return Base58NotBitcoinJ.encode(a1);
    }

    // helper
    public static String byteArrayPrint(byte[] byteData, int numberPerRow) {
        String returnString = "";
        String rawString = printHexBinary(byteData);
        int rawLength = rawString.length();
        int i = 0;
        int j = 1;
        int z = 0;
        for (i = 0; i < rawLength; i++) {
            z++;
            returnString = returnString + rawString.charAt(i);
            if (j == 2) {
                returnString = returnString + " ";
                j = 0;
            }
            j++;
            if (z == (numberPerRow * 2)) {
                returnString = returnString + "\n";
                z = 0;
            }
        }
        return returnString;
    }

    // diese routinen in java 11 an stelle von datatypeconverter.xxx nutzen
    public static String printHexBinary(byte[] bytes) {
        final char[] hexArray = "0123456789ABCDEF".toCharArray();
        char[] hexChars = new char[bytes.length * 2];
        for (int j = 0; j < bytes.length; j++) {
            int v = bytes[j] & 0xFF;
            hexChars[j * 2] = hexArray[v >>> 4];
            hexChars[j * 2 + 1] = hexArray[v & 0x0F];
        }
        return new String(hexChars);
    }

    private static String bytesToHex(byte[] bytes) {
        StringBuffer result = new StringBuffer();
        for (byte b : bytes) result.append(Integer.toString((b & 0xff) + 0x100, 16).substring(1));
        return result.toString();
    }

    static private String adjustTo64(String s) {
        switch (s.length()) {
            case 62:
                return "00" + s;
            case 63:
                return "0" + s;
            case 64:
                return s;
            default:
                throw new IllegalArgumentException("not a valid key: " + s);
        }
    }

    public static byte[] hexStringToByteArray(String s) {
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                    + Character.digit(s.charAt(i + 1), 16));
        }
        return data;
    }
}
